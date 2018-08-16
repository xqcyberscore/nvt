##########################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_read_file.inc 10986 2018-08-15 13:38:20Z cfischer $
#
# SMB Functions
#
# Authors:
# bchandra <bchandra@secpod.com>
# (an excerpt of secpod_smb_func.inc)
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 10986 $
#
##########################################################################

##########################################################################
# Function that reads the content of given file
# Param
#         share: Windows IPC Share
#        file: File path to read the content
#        offset: Position from which to start the file read
##########################################################################

# TODO: Remove once openvas-nasl-lint can handle such a missing include
# from within the same include.
if(!defined_func("kb_smb_name")) include("smb_nt.inc");

name = kb_smb_name();
domain = kb_smb_domain();
login = kb_smb_login();
pass = kb_smb_password();
port = kb_smb_transport();
soc = open_sock_tcp(port);

function GSHB_read_file(share, file, offset)
{
        if(!port){
                port = 445;
        }

        soc = open_sock_tcp(port);
        if(!soc){
                return FALSE;
        }

        r = smb_session_request(soc:soc, remote:name);
        if(!r)
        {
                close(soc);
                return FALSE;
        }

        prot = smb_neg_prot(soc:soc);
        if(!prot)
        {
                close(soc);
                return FALSE;
        }

        r = smb_session_setup(soc:soc, login:login, password:pass,
                                 domain:domain, prot:prot);
        if(!r)
        {
                close(soc);
                return FALSE;
        }

        uid = session_extract_uid(reply:r);
        if(!uid)
        {
                close(soc);
                return FALSE;
        }

        r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
        if(!r)
        {
                close(soc);
                return FALSE;
        }

        tid = tconx_extract_tid(reply:r);
        if(!tid)
        {
                close(soc);
                return FALSE;
        }

        fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
        if(!fid)
        {
                close(soc);
                return FALSE;
        }
        size = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
        if(!size)
        {
                close(soc);
                return FALSE;
        }
        content = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid,
                           count:size, off:offset);
        return content;
}
