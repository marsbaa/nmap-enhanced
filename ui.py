from typing import Any

from rich.align import Align
from rich.layout import Layout
from rich.progress import Progress, TaskID
from rich.table import Table


def create_scan_table(*, cli: str) -> Table:
    """
    Create a table for the CLI UI
    :param cli: Full Nmap arguments used on the run
    :return: Skeleton table, no data
    """
    nmap_table = Table(title=f"NMAP run info: {cli}")
    nmap_table.add_column("IP", justify="right", style="cyan", no_wrap=True)
    nmap_table.add_column("Protocol", justify="right",
                          style="cyan", no_wrap=True)
    nmap_table.add_column("Port ID", justify="right",
                          style="magenta", no_wrap=True)
    nmap_table.add_column("Service", justify="right", style="green")
    nmap_table.add_column("CPE", justify="right", style="blue")
    return nmap_table


def update_scan_table(
        *,
        scan_result: Any,
        results_table: Table,
        main_layout: Layout,
        progress: Progress,
        task_id: TaskID,
) -> None:
    print('progress', progress)
    progress.advance(task_id, 1.0)
    print('progress', progress)
    for host_data in scan_result:
        address = host_data['address']
        for port_data in host_data['ports']:
            service_info = (
                f"{port_data['service_name'].strip()} "
                f"{port_data['service_product'].strip()} "
                f"{port_data['service_version'].strip()}"
            )

            results_table.add_row(
                address,
                port_data['protocol'],
                port_data['port_id'],
                service_info,
                "\n".join(port_data['cpes'])
            )
    main_layout['Scan results'].update(
        Align.center(
            results_table,
            vertical="top"
        )
    )
