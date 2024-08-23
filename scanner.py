import re
from zipfile import ZipFile

from rich.console import Console

console = Console()

class Scanner:
    def __init__(self, file: str):
        self.file = file.replace('file:///', '')  # remove protocol
        self.options = {}
        self.links = []
        self.good_links = [
            'minecraft.org', 
            'minecraft.net',
            'netty.io',
            'optifine.net',
            'mojang.com',
            'apache.org',
            'logging.apache.org',
            'www.w3.org',
            'tools.ietf.org',
            'eclipse.org',
            'www.openssl.org',
            'sessionserver.mojang.com',
            'authserver.mojang.com',
            'api.mojang.com',
            'shader-tutorial.dev',
            's.optifine.net',
            'snoop.minecraft.net',
            'account.mojang.com',
            'bugs.mojang.com',
            'aka.ms',
            'minotar.net',
            'dominos.com',
            'cabaletta/baritone',
            'yaml.org',
            'java.sun.org',
            'com/viaversion/',
            'lwjgl.org',
            'dump.viaversion.com',
            'docs.advntr.dev',
            'jo0001.github.io',
            'viaversion.com',
            'ci.viaversion.com',
            'paulscode/sound/',
            'api.spiget.org',
            'login.live.com'
        ]

    def log(self, msg: str) -> None:
        console.print(msg, highlight=False)

    def info(self, msg: str) -> None:
        self.log(f'[cyan]{msg}[/]')

    def report(self) -> str:
        options_view = '\n'.join(f'{key.capitalize()}: {"Yes" if value else "No"}' for key, value in self.options.items())
        
        return f'''
Links: {len(self.links)} 
{options_view}
'''

    def scan(self) -> str:
        self.log(f'Scanning: {self.file}...')

        if not self.file.endswith('.jar'):
            self.info('File is not a jar executable!')
            return ''
        
        with ZipFile(self.file, 'r') as zip:
            self._process_manifest(zip)
            self._process_files(zip)

        return self.report()

    def _process_manifest(self, zip: ZipFile) -> None:
        try:
            manifest = zip.read('META-INF/MANIFEST.MF').decode()
            if 'Main-Class' in manifest:
                main_class_info = manifest[manifest.find('Main-Class:'):manifest.find('\nDev:')]
                self.log(main_class_info)
                
        except Exception:
            pass

    def _process_files(self, zip: ZipFile) -> None:
        for file in zip.filelist:
            filename = file.filename.lower()
            if 'net/minecraft' in filename and not self.options.get('minecraft'):
                self.options['minecraft'] = True

            if 'fabric.mod.json' in filename:
                self.options['fabric'] = True
                
            if 'mods.toml' in filename:
                self.options['forge'] = True

            if any(keyword in filename for keyword in ['discord', 'rpc']) and not self.options.get('discord'):
                self.options['discord'] = True

            if file.filename.endswith('.class'):
                self._process_class_file(zip, file.filename)

    def _process_class_file(self, zip: ZipFile, filename: str) -> None:
        data = zip.read(filename).decode(errors='ignore')
        self._extract_links(data, filename)

    def _extract_links(self, data: str, filename: str) -> None:
        match = re.search(r'\b(?:https?|ftp):\/\/[^\s/$.?#].[^\s]*\b', data)
        if match:
            link = ''.join(letter for letter in match.group(0) if letter.isprintable())
            if not any(g in link for g in self.good_links):
                self.links.append(f'{link} | {filename}')
                self.info(f'Found link: {link} | {filename}')
    
        match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)  # Regex for IP addresses
        if match:
            ip_address = match.group(0)
            self.links.append(f'{ip_address} | {filename}')
            self.info(f'Found IP address: {ip_address} | {filename}')