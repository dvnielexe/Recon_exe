class Config:
    def __init__(self, target: str, output: str=None, verbose: bool=False):
        self.target = target
        self.output = output
        self.verbose = verbose