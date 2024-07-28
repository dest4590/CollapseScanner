import re
from zipfile import ZipFile
from rich import print

class Scanner:
    def __init__(self, file: str):
        self.file = file.replace('file:///', '') # remove protocol
        self.discord = False
        self.minecraft = False
        self.scan_links = True
        self.links = []

    def log(self, msg: str) -> None:
        print(f'{msg}')

    def good(self, msg: str) -> None:
        self.log(f'[green]{msg}[/]')

    def info(self, msg: str) -> None:
        self.log(f'[cyan]{msg}[/]')

    def report(self) -> str:
        text = ''

        text += f'Links: {len(self.links)}'

        return text

    def scan(self) -> str:
        self.log(f'Scanning: {self.file}...')

        if not self.file.endswith('.jar'):
            self.log('File is not jar executable!')
            return ''

        with ZipFile(self.file, 'r') as zip: 
            try: 
                manifest = zip.read('META-INF/MANIFEST.MF').decode()

                if 'Main-Class' in manifest:
                    self.log(f"{manifest[manifest.find('Main-Class:'):manifest.find('\nDev:')]}")
            except Exception:
                pass

            for file in zip.filelist:
                if 'net/minecraft' in file.filename.lower() and not self.minecraft:
                    self.log('Jar is minecraft executable')
                    self.minecraft = True

                if any(keyword in file.filename.lower() for keyword in ['discord', 'rpc']) and not self.discord:
                    self.log(f'Found discord rpc: {file.filename}')
                    self.discord = True

                if file.filename.endswith('.class') and self.scan_links:
                    data = zip.read(file.filename).decode(errors='ignore')

                    match = re.search(r'\b(?:https?|ftp):\/\/[^\s/$.?#].[^\s]*\b', data)
                    
                    if match != None:
                        link = ''.join(letter for letter in match.group(0) if letter.isprintable())
                        self.links.append(f'{link} | {file.filename}')

                        if any(l in link for l in ['minecraft.org', 'optifine.net']):
                            self.good(f'Found good link: {link} | {file.filename}')

                        else:
                            self.info(f'Found link: {link} | {file.filename}')

        return self.report()