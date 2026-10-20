class Config:
    def __init__(
            self, 
            target: str, 
            output: str = None, 
            verbose: bool = False,
            wordlist: str = None,
            services: bool = False,
            urls: bool = False,
            ):
        self.target = target
        self.output = output
        self.verbose = verbose
        self.wordlist = wordlist
        self.services = services
        self.urls = urls