#!/usr/bin/env python3
"""
Generate the qedos Microkit system description (`proofgate.system`)
and sDDF driver/client configuration blobs.
"""
import argparse
import os
import sys

from sdfgen import SystemDescription, Sddf, DeviceTree

ProtectionDomain = SystemDescription.ProtectionDomain
MemoryRegion = SystemDescription.MemoryRegion
Map = SystemDescription.Map
Channel = SystemDescription.Channel


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sddf", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--sdf", required=True)
    parser.add_argument("--board", default="x86_64_generic",
                        help="Microkit board: x86_64_generic (default), qemu_virt_aarch64, rpi4b_1gb")
    parser.add_argument("--dtb", default=None, help="board DTB (required for aarch64 boards)")
    args = parser.parse_args()

    sys.path.append(os.path.join(args.sddf, "tools/meta"))
    from board import BOARDS, add_x86_hpet

    board = next(b for b in BOARDS if b.name == args.board)
    is_x86 = board.arch == SystemDescription.Arch.X86_64
    paddr_top = board.paddr_top
    if board.name.startswith("rpi4b"):
        # sDDF's rpi4b_1gb default (32 MiB) assumes a tiny image; the QEDOS image (OpenSSL + 16 MiB heaps)
        # occupies that low RAM, so place DMA/ring regions below 768 MiB instead (valid RAM ends ~0x3b400000).
        paddr_top = 0x3000_0000
    sdf = SystemDescription(board.arch, paddr_top)
    Sddf(args.sddf)

    uart_node = ethernet_node = timer_node = None
    if not is_x86:
        if args.dtb is None:
            sys.exit(f"--dtb is required for board {board.name}")
        with open(args.dtb, "rb") as f:
            dtb = DeviceTree(f.read())
        uart_node = dtb.node(board.serial)
        ethernet_node = dtb.node(board.ethernet)
        timer_node = dtb.node(board.timer)
        assert uart_node and ethernet_node and timer_node, "DTB is missing a board device node"

    # 1. Hardware & Virtualiser PDs (sDDF)
    timer_driver = ProtectionDomain("timer_driver", "timer_driver.elf", priority=102, cpu=0)
    timer_system = Sddf.Timer(sdf, timer_node, timer_driver)
    if is_x86:
        add_x86_hpet(sdf, timer_driver)

    serial_driver = ProtectionDomain("serial_driver", "serial_driver.elf", priority=100, cpu=0)
    serial_virt_tx = ProtectionDomain("serial_virt_tx", "serial_virt_tx.elf", priority=99, cpu=0)
    serial_system = Sddf.Serial(
        sdf, uart_node, serial_driver, serial_virt_tx, enable_color=False, baud_rate=board.baud_rate
    )
    if is_x86:
        serial_driver.add_ioport(SystemDescription.IoPort(0x3F8, 8, 0))

    ethernet_driver = ProtectionDomain(
        "ethernet_driver", "eth_driver.elf", priority=101, budget=100, period=400, cpu=0
    )
    if is_x86:
        hw_net_rings = MemoryRegion(sdf, "hw_net_rings", 65536, paddr=0x7A000000)
        sdf.add_mr(hw_net_rings)
        ethernet_driver.add_map(Map(hw_net_rings, 0x7000_0000, "rw"))

        virtio_net_regs = MemoryRegion(sdf, "virtio_net_regs", 0x4000, paddr=0xFE000000)
        sdf.add_mr(virtio_net_regs)
        ethernet_driver.add_map(Map(virtio_net_regs, 0x6000_0000, "rw", cached=False))

        ethernet_driver.add_irq(SystemDescription.IrqIoapic(ioapic_id=0, pin=11, vector=1, id=16))
        ethernet_driver.add_ioport(SystemDescription.IoPort(0xCF8, 4, 1))
        ethernet_driver.add_ioport(SystemDescription.IoPort(0xCFC, 4, 2))

    elif board.name.startswith("rpi4b"):
        # Pi 4 GENET driver waits on the timer during PHY reconfiguration and needs the
        # VideoCore mailbox (same wiring as the sDDF echo_server example).
        timer_system.add_client(ethernet_driver)
        mbox = MemoryRegion(sdf, "mbox", 0x10_000, paddr=0xFE00B000)
        sdf.add_mr(mbox)
        ethernet_driver.add_map(Map(mbox, 0x3000000, perms="rw", cached=False))

    net_virt_tx = ProtectionDomain(
        "net_virt_tx", "network_virt_tx.elf", priority=100, budget=20000, cpu=0
    )
    net_virt_rx = ProtectionDomain("net_virt_rx", "network_virt_rx.elf", priority=99, cpu=0)
    net_system = Sddf.Net(sdf, ethernet_node, ethernet_driver, net_virt_tx, net_virt_rx)

    # 2. qedos Application PDs (256 KiB stack per PD for ML-KEM-768 & parser state)
    tcp_pd = ProtectionDomain(
        "tcp_pd", "tcp_pd.elf", priority=97, budget=20000, stack_size=0x40000, cpu=0
    )
    tcp_net_copier = ProtectionDomain(
        "tcp_net_copier", "network_copy0.elf", priority=98, budget=20000, cpu=0
    )
    tls_pd = ProtectionDomain(
        "tls_pd", "tls_pd.elf", priority=96, budget=20000, stack_size=0x40000, cpu=0
    )
    http_pd = ProtectionDomain(
        "http_pd", "http_pd.elf", priority=95, budget=20000, stack_size=0x40000, cpu=0
    )
    policy_pd = ProtectionDomain(
        "policy_pd", "policy_pd.elf", priority=94, budget=20000, stack_size=0x40000, cpu=0
    )
    connector_pd = ProtectionDomain(
        "connector_pd", "connector_pd.elf", priority=93, budget=20000, stack_size=0x40000, cpu=0
    )

    # QED Script (opt-in: QEDOS_SCRIPT=1). script_pd runs at the LOWEST application priority so a
    # runaway script can never starve tcp/tls/http/policy/connector (LAW_017).
    script_on = os.environ.get("QEDOS_SCRIPT") == "1"
    script_pd = None
    supervisor_pd = None
    if script_on:
        script_pd = ProtectionDomain(
            "script_pd", "script_pd.elf", priority=92, budget=20000, stack_size=0x40000, cpu=0
        )
        # supervisor_pd is script_pd's Microkit PARENT: it alone holds script_pd's TCB capability (restart/stop of that
        # one PD), runs above script_pd so a hung script cannot starve it, and has no other authority except a timer
        # client and two one-way pages shared with http_pd.
        supervisor_pd = ProtectionDomain(
            "supervisor_pd", "supervisor_pd.elf", priority=93, budget=20000, stack_size=0x20000, cpu=0
        )
        SCRIPT_CHILD_ID = 10   # must match SCRIPT_CHILD_ID in sel4/pds/supervisor_pd.c
        supervisor_pd.add_child_pd(script_pd, child_id=SCRIPT_CHILD_ID)

    # QEDOS Press (opt-in: QEDOS_PRESS=1), independent of QEDOS_SCRIPT (both may be built together).
    # No supervisor parent: this PD runs no untrusted/attacker-controlled code (a fixed, signed
    # content lookup only), so the fault-containment need that motivated script_pd's supervisor does
    # not apply the same way here -- a documented, narrower-capability gap, not an oversight
    # (docs/QEDOS_PRESS_CMS.md).
    press_on = os.environ.get("QEDOS_PRESS") == "1"
    press_pd = None
    if press_on:
        press_pd = ProtectionDomain(
            "qedos_press_pd", "qedos_press_pd.elf", priority=92, budget=20000, stack_size=0x40000, cpu=0
        )

    serial_system.add_client(tcp_pd)
    timer_system.add_client(tcp_pd)
    if script_on:
        timer_system.add_client(supervisor_pd)
    net_system.add_client_with_copier(tcp_pd, tcp_net_copier)
    tcp_lwip = Sddf.Lwip(sdf, net_system, tcp_pd)

    assert serial_system.connect()
    assert serial_system.serialise_config(args.output)
    assert net_system.connect()
    assert net_system.serialise_config(args.output)
    assert timer_system.connect()
    assert timer_system.serialise_config(args.output)
    assert tcp_lwip.connect()
    assert tcp_lwip.serialise_config(args.output)

    # 3. qedos Isolated Shared Memory Regions (LAW_008, LAW_011, LAW_012)
    shm_tcp_tls = MemoryRegion(sdf, "shm_tcp_tls", 0x40000)
    shm_tls_http = MemoryRegion(sdf, "shm_tls_http", 0x40000)
    shm_http_policy = MemoryRegion(sdf, "shm_http_policy", 0x10000)
    shm_signed_config = MemoryRegion(sdf, "shm_signed_config", 0x1000)
    shm_policy_conn = MemoryRegion(sdf, "shm_policy_conn", 0x10000)
    shm_conn_http = MemoryRegion(sdf, "shm_conn_http", 0x10000)
    shm_tcp_conn = MemoryRegion(sdf, "shm_tcp_conn", 0x20000)
    tls_keystore = MemoryRegion(sdf, "tls_keystore", 0x2000)

    if script_on:
        shm_policy_script = MemoryRegion(sdf, "shm_policy_script", 0x10000)
        shm_script_http = MemoryRegion(sdf, "shm_script_http", 0x8000)
        sdf.add_mr(shm_policy_script)
        sdf.add_mr(shm_script_http)
        shm_http_sup = MemoryRegion(sdf, "shm_http_sup", 0x1000)
        shm_sup_http = MemoryRegion(sdf, "shm_sup_http", 0x1000)
        sdf.add_mr(shm_http_sup)
        sdf.add_mr(shm_sup_http)

    if press_on:
        # Sized for PG_MAX_CONNS (4) independent per-connection slots, not one shared record (see
        # pg_shm.h's pg_shm_policy_press_t/pg_shm_press_http_t _Static_assert against these sizes).
        shm_policy_press = MemoryRegion(sdf, "shm_policy_press", 0x10000)
        shm_press_http = MemoryRegion(sdf, "shm_press_http", 0x21000)
        sdf.add_mr(shm_policy_press)
        sdf.add_mr(shm_press_http)

    for mr in [
        shm_tcp_tls,
        shm_tls_http,
        shm_http_policy,
        shm_signed_config,
        shm_policy_conn,
        shm_conn_http,
        shm_tcp_conn,
        tls_keystore,
    ]:
        sdf.add_mr(mr)

    # Map regions strictly to their communicating PDs with minimal permissions:
    # - tcp_pd <-> tls_pd
    tcp_pd.add_map(Map(shm_tcp_tls, 0x3000_0000, "rw"))
    tls_pd.add_map(Map(shm_tcp_tls, 0x3000_0000, "rw"))

    # - tls_pd ONLY: read-only TLS keystore (LAW_008)
    tls_pd.add_map(Map(tls_keystore, 0x3700_0000, "r"))

    # - tls_pd <-> http_pd
    tls_pd.add_map(Map(shm_tls_http, 0x3100_0000, "rw"))
    http_pd.add_map(Map(shm_tls_http, 0x3100_0000, "rw"))

    # - http_pd <-> policy_pd
    http_pd.add_map(Map(shm_http_policy, 0x3200_0000, "rw"))
    policy_pd.add_map(Map(shm_http_policy, 0x3200_0000, "rw"))

    # - policy_pd ONLY: read-only signed configuration (LAW_011)
    policy_pd.add_map(Map(shm_signed_config, 0x3300_0000, "r"))

    # - policy_pd <-> connector_pd (connector_pd maps read/write only for ack)
    policy_pd.add_map(Map(shm_policy_conn, 0x3400_0000, "rw"))
    connector_pd.add_map(Map(shm_policy_conn, 0x3400_0000, "rw"))

    # - connector_pd <-> http_pd
    connector_pd.add_map(Map(shm_conn_http, 0x3500_0000, "rw"))
    http_pd.add_map(Map(shm_conn_http, 0x3500_0000, "rw"))

    # - connector_pd <-> tcp_pd
    connector_pd.add_map(Map(shm_tcp_conn, 0x3600_0000, "rw"))
    tcp_pd.add_map(Map(shm_tcp_conn, 0x3600_0000, "rw"))

    if script_on:
        # script_pd maps ONLY these two regions; it has no tls_keystore, signed config, net, timer or IRQ (LAW_014/018/022)
        policy_pd.add_map(Map(shm_policy_script, 0x3800_0000, "rw"))
        script_pd.add_map(Map(shm_policy_script, 0x3800_0000, "rw"))
        script_pd.add_map(Map(shm_script_http, 0x3900_0000, "rw"))
        http_pd.add_map(Map(shm_script_http, 0x3900_0000, "rw"))
        # supervisor <-> http_pd: two one-way pages (single writer each, enforced by the MMU permissions)
        http_pd.add_map(Map(shm_http_sup, 0x3A00_0000, "rw"))
        supervisor_pd.add_map(Map(shm_http_sup, 0x3A00_0000, "r"))
        supervisor_pd.add_map(Map(shm_sup_http, 0x3B00_0000, "rw"))
        http_pd.add_map(Map(shm_sup_http, 0x3B00_0000, "r"))

    if press_on:
        # qedos_press_pd maps ONLY these two regions; it has no tls_keystore, signed config, net,
        # timer or IRQ. Its content bundle is its own read-only .rodata, not a shared region.
        policy_pd.add_map(Map(shm_policy_press, 0x3C00_0000, "rw"))
        press_pd.add_map(Map(shm_policy_press, 0x3C00_0000, "rw"))
        press_pd.add_map(Map(shm_press_http, 0x3D00_0000, "rw"))
        http_pd.add_map(Map(shm_press_http, 0x3D00_0000, "rw"))

    # 4. qedos IPC Channels
    sdf.add_channel(Channel(tcp_pd, tls_pd, a_id=10, b_id=1))
    sdf.add_channel(Channel(tls_pd, http_pd, a_id=2, b_id=1))
    sdf.add_channel(Channel(http_pd, policy_pd, a_id=2, b_id=1))
    sdf.add_channel(Channel(policy_pd, connector_pd, a_id=2, b_id=1))
    sdf.add_channel(Channel(connector_pd, http_pd, a_id=2, b_id=3))
    sdf.add_channel(Channel(connector_pd, tcp_pd, a_id=3, b_id=11))

    if script_on:
        sdf.add_channel(Channel(policy_pd, script_pd, a_id=3, b_id=1))
        sdf.add_channel(Channel(script_pd, http_pd, a_id=2, b_id=4))
        sdf.add_channel(Channel(http_pd, supervisor_pd, a_id=5, b_id=1))

    if press_on:
        sdf.add_channel(Channel(policy_pd, press_pd, a_id=4, b_id=1))
        sdf.add_channel(Channel(press_pd, http_pd, a_id=2, b_id=6))

    for pd in [
        serial_driver,
        serial_virt_tx,
        ethernet_driver,
        net_virt_tx,
        net_virt_rx,
        timer_driver,
        tcp_net_copier,
        tcp_pd,
        tls_pd,
        http_pd,
        policy_pd,
        connector_pd,
    ] + ([supervisor_pd] if script_on else []) + ([press_pd] if press_on else []):   # script_pd is nested inside supervisor_pd (child PD)
        sdf.add_pd(pd)

    out_path = os.path.join(args.output, args.sdf)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(sdf.render())
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
