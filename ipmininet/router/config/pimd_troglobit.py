from .base import RouterDaemon

class Pimd(RouterDaemon):
    """ This class configure the pim Daemon which can be found here:
        https://github.com/troglobit/pimd
    """
    NAME = 'pimd'
    KILL_PATTERNS = (NAME,)

    def __init__(self,node,*args,**kwargs):
        super().__init__(node=node,*args,**kwargs)
        if "cfg" in kwargs:
            self.custom_config = kwargs["cfg"]


    @property
    def startup_line(self):
        return '{name} -f --config={cfg}'.format(name=self.NAME,cfg=self.cfg_filename)

    @property
    def dry_run(self):
        #does not check te config file launch the daemon anyway
        if hasattr(self,'custom_config'):
            return '{name} --config={cfg}'.format(name=self.NAME,cfg=self.custom_config)
        else:
            return '{name} --config={cfg}'.format(name=self.NAME,cfg=self.cfg_filename)

    def set_defaults(self,defaults):
        super().set_defaults(defaults)

    def build(self):
        cfg = super().build()
        return cfg
