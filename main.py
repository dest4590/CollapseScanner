import os

from rich import print
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from scanner import Scanner


class CLI:
    def __init__(self):
        self.menu_text = '\n[bold]CollapseScanner[/] - Minecraft clients scanning tool for various threats\n'
        self.menu_text += '[yellow]warning:[/] scanner may give false positives, use at your own risk\n'

    def prompt_file_selection(self) -> str:
        return input('Drag and drop the file here: ').strip()

    def run(self) -> None:
        print(self.menu_text)
        file_path = self.prompt_file_selection()
        
        with Progress(SpinnerColumn(), TextColumn("[blue][progress.description]{task.description} {task.fields[index]}/{task.fields[total_files]}[/]"), BarColumn(pulse_style='gray'), TextColumn("[progress.description]"), transient=True) as progress:
            task_id = progress.add_task(f"Scanned", index=0, total_files=0, total=None)
            
            scanner = Scanner(file_path, progress, task_id)
            report = scanner.scan()

        progress.print(report)

if __name__ == '__main__':
    cli = CLI()
    cli.run()