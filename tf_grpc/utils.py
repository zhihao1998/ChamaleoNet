
def import_bfrt_grpc():
    """ tries setting python path for imports if not found """

    import sys
    import os
    # Define Python version string
    PYTHON3_VER = '{}.{}'.format( sys.version_info.major, sys.version_info.minor)
    # Construct the paths using os.path.expandvars and os.path.join
    #path1 = os.path.expandvars(os.path.join('$SDE', 'install', 'lib', 'python' + verstr, 'site-packages', 'tofino'))
    #path2 = os.path.expandvars(os.path.join('$SDE', 'install', 'lib', 'python' + verstr, 'site-packages', 'tofino', 'bfrt_grpc'))

    SDE_INSTALL = os.environ.get('SDE_INSTALL')

    SDE_PYTHON3 = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages')
    sys.path.append(SDE_PYTHON3)
    sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
    sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

    # Print sys.path for debugging
    print("sys.path:", sys.path)
    import bfrt_grpc.client as gc
    return gc