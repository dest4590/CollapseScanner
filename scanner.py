import re
from zipfile import ZipFile

from rich.console import Console
from rich.progress import Progress, TaskID

console = Console()

class Scanner:
    def __init__(self, file: str, progress_bar: Progress, task_id: TaskID) -> None:
        self.file = file.replace('file:///', '')  # remove protocol
        self.progress_bar = progress_bar
        self.task_id = task_id
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
            'login.live.com',
            'slf4j.org',
        ]

    def log(self, msg: str) -> None:
        self.progress_bar.print(msg, highlight=False)

    def info(self, msg: str) -> None:
        self.progress_bar.print(f'[cyan]{msg}[/]')

    def report(self) -> str:
        options_view = '\n'.join(f'{str(key).title().replace('_', ' ')}: {"Yes" if value else "No"}' for key, value in self.options.items())
        
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
        except Exception as e:
            self.log(f"Error processing manifest: {e}")

    def _process_files(self, zip: ZipFile) -> None:
        index = 0
        
        self.progress_bar.update(self.task_id, total_files=len(zip.filelist))
        
        for file in zip.filelist:
            filename = file.filename.lower()
            index += 1
            
            self.progress_bar.update(self.task_id, index=index)
            
            if 'net/minecraft' in filename and not self.options.get('minecraft'):
                self.options['minecraft'] = True

            if 'fabric.mod.json' in filename:
                self.options['fabric'] = True

            if 'mods.toml' in filename:
                self.options['forge'] = True

            if any(keyword in filename for keyword in ['rpc']) and not self.options.get('discord_RPC'):
                self.options['discord_RPC'] = True

            if file.filename.endswith('.class'):
                self._process_class_file(zip, file.filename)

    def _process_class_file(self, zip: ZipFile, filename: str) -> None:
        try:
            data = zip.read(filename).decode(errors='ignore')
            self._extract_links(data, filename)
        except Exception as e:
            self.log(f"Error processing class file {filename}: {e}")

    def _extract_links(self, data: str, filename: str) -> None:
        try:
            # Regex for URLs
            url_match = re.search(r'\b(?:https?|ftp|ssh|telnet|file):\/\/[^\s/$.?#].[^\s]*\b', data)
            
            if url_match:
                link = ''.join(letter for letter in url_match.group(0) if letter.isprintable())
                if not any(g in link for g in self.good_links):
                    self.links.append(f'{link} | {filename}')
                    self.info(f'Found link: {link} | {filename}')
            
            # Regex for IP addresses
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)
            
            if ip_match:
                ip_address = ip_match.group(0)
                self.links.append(f'{ip_address} | {filename}')
                self.info(f'Found IP address: {ip_address} | {filename}')
        except Exception as e:
            self.log(f"Error extracting links from {filename}: {e}")