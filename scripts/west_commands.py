'''west_extensions.py

West command extensions for kAFL.'''

import os

from west.commands import WestCommand  # your extension must subclass this
from west.manifest import Manifest
from west import log

class EnvCmd(WestCommand):

    def __init__(self):
        super().__init__(
            'env',  # gets stored as self.name
            'shell env helper',  # self.help
            'Return base shell env setup for kAFL projects'
            )

    def do_add_parser(self, parser_adder):

        parser = parser_adder.add_parser(self.name,
                                         help=self.help,
                                         description=self.description)

        return parser

    def do_run(self, args, unknown_args):
        env = Manifest.from_file()

        try:
            kafl_path = env.get_projects(['kafl'])[0].abspath
        except ValueError as e:
            kafl_path = env.get_projects(['manifest'])[0].abspath

        capstone_path = env.get_projects(['capstone'])[0].abspath
        libxdc_path = env.get_projects(['libxdc'])[0].abspath
        qemu_path = env.get_projects(['qemu'])[0].abspath


        kafl_bin_path = os.path.join(kafl_path, 'kAFL-Fuzzer')
        if not os.path.exists(kafl_bin_path):
            log.wrn("Could not find kAFL-Fuzzer in %s" % kafl_path)
            kafl_bin_path = ""

        qemu_bin_path = os.path.join(qemu_path, 'x86_64-softmmu/qemu-system-x86_64')
        if not os.path.exists(qemu_bin_path):
            log.wrn("Could not find kAFL Qemu binary in %s" % qemu_path)
            qemu_bin_path = ""

        # project executables
        print("KAFL_BIN_PATH=%s" % kafl_bin_path)
        print("KAFL_QEMU_PATH=%s" % qemu_bin_path)

        # project libraries/includes
        print("C_INCLUDE_PATH=%s/include:%s" % (capstone_path, libxdc_path))
        print("LIBRARY_PATH=%s:%s/build" % (capstone_path, libxdc_path))
        print("LD_LIBRARY_PATH=%s:%s/build" % (capstone_path, libxdc_path))


class PathCmd(WestCommand):

    def __init__(self):
        super().__init__(
            'path',  # gets stored as self.name
            'get project path',  # self.help
            'Get a projects path; shortcut to west list -f {abspath}',
            accepts_unknown_args=True)

    def do_add_parser(self, parser_adder):

        parser = parser_adder.add_parser(self.name,
                                         help=self.help,
                                         description=self.description)

        return parser

    def do_run(self, args, extra_args):
        env = Manifest.from_file()

        for query in extra_args:
            try:
                prj = env.get_projects([query])
                print(prj[0].abspath)
            except ValueError as e:
                # check if `manifest` is the kAFL repo..
                if query != 'kafl':
                    log.err("Could not find %s in west projects. Try `west list`." % query)
                    return
                try:
                    # check if manifest repo is kAFL
                    kafl_path = env.get_projects(['manifest'])[0].abspath
                    if os.path.exists(kafl_path + '/kAFL-Fuzzer'):
                        log.wrn("Returning `manifest` repo path for query `%s`.." % query)
                        print(kafl_path)
                except ValueError as e:
                    log.err("Could not find %s in west projects. Try `west list`." % query)
            except Exception as e:
                log.err(str(e))
