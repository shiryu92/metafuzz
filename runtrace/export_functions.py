#
#

from __future__ import with_statement

import idautils
import idc
import os
import md5
import sqlite3

from win32api import GetFileVersionInfo, LOWORD, HIWORD

def get_version_number (filename):
  info = GetFileVersionInfo (filename, "\\")
  ms = info['FileVersionMS']
  ls = info['FileVersionLS']
  return ".".join(str(i) for i in [HIWORD (ms), LOWORD (ms), HIWORD (ls),
                                   LOWORD (ls)])


def get_filename():
    path, filename = os.path.split(idc.GetIdbPath())
    #filename, ext = os.path.splitext(filename)
    return filename

def get_segments():
    return [(ea, idc.SegEnd(ea)) for ea in idautils.Segments()]

def get_functions_in_range(start_ea, end_ea):
    return list(idautils.Functions(start_ea, end_ea))

def get_function_name(ea):
    return idc.GetFunctionName(ea)

def get_functions():
    segments = get_segments()

    for seg_num, seg in enumerate(segments):
        print 'Segment[%d/%d]' % (seg_num+1, len(segments))

        for address in get_functions_in_range(seg[0], seg[1]):
            name = get_function_name(address)

            yield (address, name)

def get_module():
    path = get_filename()
    name = os.path.split(path)[-1]

    h = md5.md5()
    h.update(open(path).read())
    md5sum = h.hexdigest()

    return (name, path, md5sum)

def new_module(db):
    cur = db.cursor()
    name, path, md5sum = get_module()

    cur.execute('''INSERT INTO modules (name, path, md5) VALUES (?,?,?)''',
                   (name, path, md5sum))
    module_id = cur.lastrowid
    return module_id

def add_functions(db, module_id):
    cur = db.cursor()

    cur.executemany('''INSERT INTO functions (address, name, module_id)
                       VALUES (?,?,?)''',
                      [(a,n,module_id) for a,n in get_functions()]
                   )
    db.commit()

def export_functions(path):
    db = sqlite3.connect(path)

    try:
        module_id = new_module(db)
        add_functions(db, module_id)
    except:
        db.rollback()
    else:
        db.commit()
    finally:
        db.close()

def main():
    path = "C:\\runtracer\\modules.sqlite"
    export_functions(path)

if __name__ == "__main__":
    main()
