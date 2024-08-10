from rich import print

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
        scanner = Scanner(file_path)
        report = scanner.scan()
        print(report)

if __name__ == '__main__':
    cli = CLI()
    cli.run()