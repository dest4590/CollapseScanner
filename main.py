from scanner import Scanner

class CLI:
    def __init__(self):
        self.text = ''

        self.text += '1. Scan file'

    def select_file(self):
        return input('Drag n drop file here: ')
    
    def run(self):
        scanner = Scanner(self.select_file())
        report = scanner.scan()

        print(report)

cli = CLI()

if __name__ == '__main__':
    cli.run()