###############################################################################
# OpenVAS Include File
# $Id: secpod_smb_func.inc 10707 2018-08-01 10:58:06Z cfischer $
#
# SMB Functions
#
# Authors:
# bchandra <bchandra@secpod.com>
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
# $Revision: 10707 $
#
###############################################################################

###############################################################################
# GetVer(), bin_word(), bin_dword() are a derivative of smbcl_func.inc available
# in the OpenVAS repository
# This script was written by Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# This script is released under the GNU GPLv2
###############################################################################

# Get File version or product version reading through a file. An
# offset can be sent indicating the start location. By default
# file version is read, if product version is required, we can
# indicate verstr="prod"

function GetVersion( socket, uid, tid, fid, offset, verstr, debug ) {

  local_var socket, uid, tid, fid, offset, verstr, debug;
  local_var fsize, data, i, offset, tmp, version, ver, vers, len, ver_len, retVal;

  if( isnull( socket ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#GetVersion" );
  if( isnull( uid ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#GetVersion" );
  if( isnull( tid ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#GetVersion" );
  if( isnull( fid ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#GetVersion" );

  pattern = "F?i?l?e?V?e?r?s?i?o?n";
  if( verstr == "prod" ) {
    pattern = "P?r?o?d?u?c?t?V?e?r?s?i?o?n";
  } else if( verstr ) {
    pattern = verstr;
  }

  patlen = strlen( pattern );

  fsize = smb_get_file_size( socket:socket, uid:uid, tid:tid, fid:fid );

  if( isnull( offset ) ) {
    if( fsize < 180224 ) {
      offset = 0;
    } else {
      offset = fsize - 180224;
    }
  }

  if( offset < 0 ) {
    offset = fsize + offset;
  }

  start = offset;

  if( start < 0 || start > fsize ) {
    start = fsize/2;
  }

  offset = start;
  chunk = 16384;

  for( i = 0; offset < fsize; i++ ) {
    tmp = ReadAndX( socket:socket, uid:uid, tid:tid, fid:fid, count:chunk, off:offset );
    if( tmp ) {
      if( pattern == "build" ) {
        tmp = str_replace( find:raw_string(0), replace:"", string:tmp );
      } else {
        tmp = str_replace( find:raw_string(0), replace:"?", string:tmp );
      }

      data += tmp;
      version = strstr( data, pattern );
      if( version ) {
        len = strlen( version );
        for( i = patlen; i < len; i++ ) {
          if( ! isnull( version[i] ) ) {
            if( ( ord( version[i] ) < ord( "0" ) || ord( version[i] ) > ord( "9" ) ) &&
                ( version[i] != "." && version[i] != "," && version[i] != " " &&
                version[i] != "?" ) ) {
              ver_len = strlen( ver );
              if( ver_len > 0 && ver[ver_len - 1] == "." ) {
                vers = split( ver, sep:".", keep:FALSE );
                foreach item( vers ) {
                  retVal += string( "." + item );
                }
                retVal -= string( "." );
                return retVal;
              }
              return ver;
            } else if( version[i] == "," || version[i] == "." ) {
              ver += ".";
            } else if( ver && version[i] == "?" && version[i+1] == "?" ) {
              return ver;
            } else if( version[i] == " "||version[i] == "?" ) {
            } else {
              ver += version[i];
            }
          }
        }
      }
      offset += chunk;
    }
  }
  return NULL;
}

# @brief Enumerates existing registry values for a given key.
#        It will gather all required info about the SMB registry
#        from the knowledge base.
#
# @param key the registry key to enumerate for values
# @param type the registry type HKCU, HKU or HKLM to enumerate
#
# @return A list containing the existing values of the given key, otherwise an empty list
#
function registry_enum_values( key, type ) {

  local_var key, type, list, soc, r, prot, uid, tid, pipe, handle;
  local_var name, login, pass, domain, port;

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  # This function is mostly called in foreach loops. Make sure to always return
  # an empty list here instead of the previously behavior to return FALSE if any of
  # the calles between the last return failed. This old  behavior had caused a
  # nasl_array_iterator: # unhandled type 57 (0x39) if FALSE was returned when failed.
  list = make_list();

  if( ! key ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_enum_values" );
    return list;
  }

  if( ! type ) type = "HKLM";
  if( ! port ) port = 445;

  soc = open_sock_tcp( port );
  if( ! soc ) {
    return list;
  }

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    close( soc );
    return list;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    close( soc );
    return list;
  }

  r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
  if( ! r ) {
    close( soc );
    return list;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return list;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:"IPC$" );
  if( ! r ) {
    close( soc );
    return list;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    close( soc );
    return list;
  }

  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return list;
  }

  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return list;
  }

  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return list;
  }

  if( type == "HKLM" ) {
    handle = registry_open_hklm( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKU" ) {
    handle = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCU" ) {
    handle = registry_open_hkcu( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else {
    close( soc );
    return list;
  }

  if( ! handle ) {
    close( soc );
    return list;
  }

  r = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle );
  if( ! r ) {
    close( soc );
    return list;
  }

  list = registry_enum_value( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );
  close( soc );

  # Always return a list for the reasons explained above
  if( typeof( list ) != "array" ) list = make_list();

  return list;
}

# @brief Enumerates registry keys via SMB. It will gather
#        all required info about the SMB registry
#        from the knowledge base.
#
# @param key the registry key to enumerate
# @param type the registry type HKCU, HKU or HKLM to enumerate
#
# @return A list containing the existing registry keys, otherwise an empty list
#
function registry_enum_keys( key, type ) {

  local_var key, type, list, soc, r, prot, uid, tid, pipe, handle;
  local_var name, login, pass, domain, port;

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  # This function is mostly called in foreach loops. Make sure to always return
  # an empty list here instead of the previously behavior to return FALSE if any of
  # the calles between the last return failed. This old  behavior had caused a
  # nasl_array_iterator: # unhandled type 57 (0x39) if FALSE was returned when failed.
  list = make_list();

  if( ! key ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_enum_keys" );
    return list;
  }

  if( ! type ) type = "HKLM";
  if( ! port ) port = 445;

  soc = open_sock_tcp( port );
  if( ! soc ) return list;

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    close( soc );
    return list;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    close( soc );
    return list;
  }

  r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
  if( ! r ) {
    close( soc );
    return list;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return list;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:"IPC$" );
  if( ! r ) {
    close( soc );
    return list;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    close( soc );
    return list;
  }

  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return list;
  }

  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return list;
  }

  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return list;
  }

  if( type == "HKLM" ) {
    handle = registry_open_hklm( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKU" ) {
    handle = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCU" ) {
    handle = registry_open_hkcu( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else {
    close( soc );
    return list;
  }
  
  if( ! handle ) {
    close( soc );
    return list;
  }

  r = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle );
  if( ! r ) {
    close( soc );
    return list;
  }

  list = registry_enum_key( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );
  close( soc );

  # Always return a list for the reasons explained above
  if( typeof( list ) != "array" ) list = make_list();

  return list;
}


################################################################################
# Open the given file
# param:
#       share: IPC Share, ex: $C
#       file: File path
################################################################################

function open_file( share, file ) {

  local_var share, file, soc, r, prot, uid, tid;
  local_var name, login, pass, domain, port;

  if( isnull( share ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#open_file" );
  if( isnull( file ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#open_file" );

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  if( ! port ) port = 445;

  soc = open_sock_tcp( port );
  if( ! soc ) return FALSE;

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    close( soc );
    return FALSE;
  }

  r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return FALSE;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:share );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    close( soc );
    return FALSE;
  }

  r = OpenAndX( socket:soc, uid:uid, tid:tid, file:file );
  if( r ) smb_close_request( soc:soc, uid:uid, tid:tid, fid:r );

  close( soc );
  return r;
}

##########################################################################
# Get the file size for a given file
# param:
#       share: Windows IPC Share
#       file: Path to a given file
##########################################################################

function get_file_size( share, file ) {

  local_var share, file, soc, r, prot, uid, tid, fid, fileSize;
  local_var name, login, pass, domain, port;

  if( isnull( share ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#get_file_size" );
  if( isnull( file ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#get_file_size" );

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  if( ! port ) port = 445;

  soc = open_sock_tcp( port );
  if( ! soc ) return FALSE;

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    close( soc );
    return FALSE;
  }

  r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return FALSE;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:share );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    close( soc );
    return FALSE;
  }

  fid = OpenAndX( socket:soc, uid:uid, tid:tid, file:file );
  if( ! fid ) {
    close( soc );
    return FALSE;
  }

  fileSize = smb_get_file_size( socket:soc, uid:uid, tid:tid, fid:fid );
  smb_close_request( soc:soc, uid:uid, tid:tid, fid:fid );
  close( soc );

  if( fileSize ) {
    return fileSize;
  }
}

##########################################################################
# Function that reads the content of given file
# param:
#       share: Windows IPC Share
#       file: File path to read the content
#       offset: Position from which to start the file read
#       count: Number of bytes to readh from offset
##########################################################################

function read_file( share, file, offset, count ) {

  local_var share, file, offset, count, soc, r, prot, uid, tid, fid, content;
  local_var name, login, pass, domain, port;

  if( isnull( share ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#open_file" );
  if( isnull( file ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#read_file" );
  if( isnull( offset ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#offset#-#read_file" );
  if( isnull( count ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#count#-#read_file" );

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  if( ! port ) port = 445;

  soc = open_sock_tcp( port );
  if( ! soc ) return FALSE;

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  prot = smb_neg_prot(soc:soc);
  if( ! prot ) {
    close( soc );
    return FALSE;
  }

  r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return FALSE;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:share );
  if( ! r ) {
    close( soc );
    return FALSE;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    close( soc );
    return FALSE;
  }

  fid = OpenAndX( socket:soc, uid:uid, tid:tid, file:file );
  if( ! fid ) {
    close( soc );
    return FALSE;
  }

  content = ReadAndX( socket:soc, uid:uid, tid:tid, fid:fid, count:count, off:offset );
  smb_close_request( soc:soc, uid:uid, tid:tid, fid:fid );
  close( soc );
  return content;
}

function GetVer( file, share, prodvers ) {

  local_var pe_offset, sections_cnt, sections_offset, sections_data, i, rsrc_start, rsrc_virtstart;
  local_var dir_data, dir_offset, dir_entries, sub_dir, dir_tmp, vs_data, vs_length, reply, recurs, max_recurs, vs_offset;
  local_var itr, it, file, share, prodvers;

  if( isnull( share ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#GetVer" );
  if( isnull( file ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#GetVer" );

  if( isnull( prodvers ) ) prodvers = 0;

  pe_offset = bin_word( data:read_file( share:share, file:file, offset:60, count:2 ) );

  if( read_file( share:share, file:file, offset:pe_offset, count:2 ) != "PE" ) {
    return NULL;
  }

  sections_cnt = bin_word( data: read_file(share:share, file:file, offset:pe_offset+6, count:2 ) );
  section_offset = pe_offset + bin_word( data:read_file(share:share, file:file, offset:pe_offset+20, count:2 ) ) + 24;
  rsrc_start = NULL;
  max_recurs = 20;

  for( itr = 0; itr < sections_cnt; itr++ ) {
    sections_data = read_file( share:share, file:file, offset:section_offset + itr * 40, count:40 );
    if( sections_data && substr( sections_data, 0, 4 ) == ".rsrc" ) {
      rsrc_start = bin_dword( data:substr( sections_data, 20 ) );
      rsrc_virtstart = bin_dword( data:substr( sections_data, 12 ) );
      break;
    }
    if( itr > max_recurs ) {
      break;
    }
  }
  if( isnull( rsrc_start ) ) {
    return NULL;
  }

  dir_data = read_file( share:share, file:file, offset:rsrc_start, count:16 );
  dir_entries = bin_word( data:substr( dir_data,12 ) ) + bin_word( data:substr( dir_data, 14 ) );
  dir_offset = NULL;
  sub_dir = 0;
  max_recurs = 100;
  recurs = 0;

  for( it = 0; it < dir_entries; it++ ) {
    dir_data = read_file( share:share, file:file, offset:rsrc_start + 16 + it * 8, count:8 );
    if( bin_dword( data:substr( dir_data, 0 ) ) == 0x10 ) {

      repeat {
        dir_tmp = bin_dword( data:substr( dir_data, 4 ) );
        if( ( dir_tmp & 0x80000000 ) == 0x80000000 ) {
          dir_offset = dir_tmp - 0x80000000;
          sub_dir = 1;
        } else {
          dir_offset = dir_tmp;
          sub_dir = 0;
        }
        dir_data = read_file( share:share, file:file, offset:rsrc_start + dir_offset + 16, count:8 );
        if( strlen( dir_data ) != 8 ) {
          return NULL;
        }
        if( ++recurs > max_recurs ) {
          return NULL;
        }
      }
      until sub_dir == 0;
      break;
    }
    if( it > max_recurs ) {
      break;
    }
  }

  if( isnull( dir_offset ) ) {
    return NULL;
  }

  dir_data = read_file( share:share, file:file, offset:rsrc_start + dir_offset, count:4 );
  dir_offset = bin_dword( data:substr( dir_data, 0 ) );
  rsrc_start = rsrc_start + ( dir_offset - rsrc_virtstart );
  vs_data = read_file( share:share, file:file, offset:rsrc_start, count:2 );
  if( ! vs_data ) {
    return NULL;
  }

  vs_length = bin_word( data:substr( vs_data, 0 ) );
  vs_data = read_file( share:share, file:file, offset:rsrc_start, count:vs_length );

  if( bin_dword( data:substr( vs_data, 40 ) ) != 0xfeef04bd ) {
    return NULL;
  }

  if( prodvers == 0 ) {
    vs_offset = 48;
  } else {
    vs_offset = 56;
  }

  reply = NULL;
  reply = string( ( bin_dword( data:substr( vs_data, vs_offset ) ) >>> 16) + "." );
  reply = reply + string( ( bin_dword( data:substr( vs_data, vs_offset ) ) & 0xffff) + "." );
  reply = reply + string( ( bin_dword( data:substr( vs_data, vs_offset + 4 ) ) >>> 16) + "." );
  reply = reply + string( ( bin_dword( data:substr( vs_data, vs_offset + 4 ) ) & 0xffff ) );
  return reply;
}

function bin_word( data ) {

  local_var data, datatype;

  if( isnull( data ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#open_file" );

  ##Make sure type is not int
  datatype = typeof( data );
  if( datatype == "int" ) {
    return NULL;
  }

  if( ! data ) {
    return 0;
  } else if( ! isnull( data[0] ) && ! isnull( data[1] ) ) {
    return( ord( data[0] ) + ( ord( data[1] ) << 8 ) );
  }
}

function bin_dword( data ) {

  local_var data, datatype;

  if( isnull( data ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#open_file" );

  ##Make sure type is not int
  datatype = typeof( data );
  if( datatype == "int" ) {
    return NULL;
  }

  if( ! data ){
    return 0;
  } else {
    if( ! isnull( data[0] ) && ! isnull( data[1] ) ) {
      return( ord( data[0] ) + ( ord( data[1] ) << 8 ) + ( ord( data[2] ) << 16 ) + ( ord( data[3] ) << 24 ) );
    }
  }
}

function GetVersionFromFile( file, verstr ) {

  local_var file, share, verstr, mshare, soc, r, prot, uid, tid, ver;
  local_var name, login, pass, domain, port;

  if( isnull( file ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#GetVersionFromFile" );

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  mshare = ereg_replace( pattern:"([A-Z]):.*", replace:"\1$", string:file );
  file = ereg_replace( pattern:"[A-Z]:(.*)", replace:"\1", string:file );

  soc = open_sock_tcp( port );
  if( ! soc ) return NULL;

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    close(soc);
    return NULL;
  }

  r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    close( soc );
    return NULL;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:mshare );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    close( soc );
    return NULL;
  }

  fid = OpenAndX( socket:soc, uid:uid, tid:tid, file:file );
  if( ! fid ) {
    close( soc );
    return NULL;
  }

  if( isnull( verstr ) ) {
    ver = GetVersion( socket:soc, uid:uid, tid:tid, fid:fid );
  } else {
    ver = GetVersion( socket:soc, uid:uid, tid:tid, fid:fid, verstr:verstr );
  }

  close( soc );
  return ver;
}
