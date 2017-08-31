###############################################################################
# OpenVAS Vulnerability Test
# $Id: version_func.inc 6738 2017-07-17 10:53:33Z cfischer $
#
# Helper functions for SSH-based target host access
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
# $Revision: 6738 $
#
###############################################################################

# XXX: the version tests should be eventually consolidated with
# the methods from revisions-lib.inc.

function find_bin( prog_name, sock ) {

  local_var r, whe, whi, cl, prog_name, sock;

  whe = "";
  whi = "";

  if( get_kb_item( "no_linux_shell" ) ) return;

  if( ! prog_name ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prog_name#-#find_bin" );

  if( ! sock ) {
    sock = ssh_login_or_reuse_connection();
  }

  if( sock ) {

    cl = check_locate( sock:sock );

    if( cl ) {
      r = split( ssh_cmd( socket:sock, cmd:"locate -ei *bin/" + prog_name, timeout:60 ) );
    } else {
      r = NULL;
    }

  } else {
     r = NULL;
  }

  if( "bin/" + prog_name >!< r ) {
    if( sock ) {
      whe = ssh_cmd( socket:sock, cmd:"whereis -b " + prog_name, timeout:60 );
      if( "bin/" + prog_name >< whe ) {
        r = split( substr( whe - ( prog_name + ":" ), 1 ), sep:" " );
      } else {
        r = NULL;
      }
    }
  }

  if( isnull( r ) ) {
    if( sock ) {
      whi = ssh_cmd( socket:sock, cmd:"which -a " + prog_name, timeout:60 );
      if( ( "which: no "+prog_name ) >!< whi ) {
        r = split( whi );
      } else {
        r = NULL;
      }
    }
  }

  return( r );
}

function find_file( file_name, file_path, useregex, regexpar, sock ) {

  local_var r, f, fname, lparam, cl, file_name, file_path, useregex, regexpar, sock;

  if( get_kb_item( "no_linux_shell" ) ) return;

  if( ! file_name ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#find_file" );

  r = NULL;

  if( useregex ) {
    lparam = "-eir";
  } else {
    lparam = "-ei";
  }

  use_find = get_kb_item( "Enable/find" );
  descend_directories = get_kb_item( "Descend/OFS" );

  if( isnull( use_find ) ) use_find="yes";
  if( isnull( descend_directories ) ) descend_directories="yes";

  fname = ereg_replace( pattern:"\*.+", string:file_name, replace:"" );

  if( ! sock ) {
    sock = ssh_login_or_reuse_connection();
  }

  if( sock ) {

    cl = check_locate( sock:sock );

    if ( cl ) {
      r = split(ssh_cmd(socket:sock, cmd:"locate "+lparam+" "+raw_string(0x22)+file_path+file_name+regexpar+raw_string(0x22), timeout:60));
    } else {
      r = NULL;
    }

    if( fname >!< r && ( "yes" >< use_find ) ) {
      if( ! isnull( file_path ) ) {

        cmd = "find " + raw_string( 0x22 ) + file_path + raw_string( 0x22 );

        if( "no" >< descend_directories ) {
          cmd += " -xdev";
        }

        cmd += " -maxdepth 7 -mindepth 1";
        cmd += ' \\( -path "*/proc" -o -path "/dev" -o -path "/sys" -o -path "/media" -o -path "/tmp" -o -path "/var" \\) -prune -o ';
        cmd += " -name " + raw_string( 0x22 );
        cmd += file_name + raw_string( 0x22 ) +" -a  -type f  -print 2>/dev/null";

        f = split( ssh_cmd( socket:sock, cmd:cmd, timeout:60 ) );

      }
    }
  }

  if( fname >!< r ) {
    if( fname >< f && "No such file or directory" >!< f ) {
      r = f;
    } else {
      r = NULL;
    }
  }
  return( r );
}

function get_bin_version( full_prog_name, version_argv, ver_pattern, sock ) {

  local_var loc_version, r, report, full_prog_name, version_argv, ver_pattern;

  if( get_kb_item( "no_linux_shell" ) ) return;

  if( ! full_prog_name ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#full_prog_name#-#get_bin_version" );
  if( ! version_argv ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version_argv#-#get_bin_version" );
  if( ! ver_pattern ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ver_pattern#-#get_bin_version" );

  full_prog_name = chomp( full_prog_name );
  version_argv = chomp( version_argv );

  if( ! sock) {
    sock = ssh_login_or_reuse_connection();
  }

  if( sock ) {
    r = ssh_cmd( socket:sock, cmd:full_prog_name + " " + version_argv, timeout:60 );
  }

  # e.g. /bin/sh: 1: /usr/share/bash-completion/completions/xfreerdp: Permission denied
  if( ": Permission denied" >< r ) return;

  loc_version = eregmatch( pattern:ver_pattern, string:r );
  if( loc_version != NULL ) loc_version[max_index( loc_version )] = r;
  return( loc_version );
}

function get_string_version( text, ver_pattern ) {

  local_var loc_version, text, ver_pattern;

  if( ! text ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#text#-#get_string_version" );

  if( isnull( ver_pattern) ) {           # Standard Version Pattern for most cases
    ver_pattern = "([0-9\.]+)";
  }

  loc_version = eregmatch( pattern:ver_pattern, string:text );
  if( loc_version != NULL ) loc_version[max_index( loc_version )] = text;
  return( loc_version );
}

function version_is_less( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_less" );
  if( ! test_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_less" );
  return( version_test( version:version, test_version:test_version, less:TRUE, icase:icase, debug:debug ) );
}

function version_is_equal( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_equal" );
  if( ! test_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_equal" );
  return( version_test( version:version, test_version:test_version, less:FALSE, icase:icase, debug:debug ) );
}

function version_test( version, test_version, less, icase, debug ) {

  # TODO: Implement 1.0.0a > 1.0.0alpha/beta/rc

  local_var ver_ary, test_ary, ver_num, ver_sep, i, r, s, char_found, test_prerelease, ver_prerelease;
  local_var version, test_version, less, icase, debug;

  if( isnull( version ) || version == "" || version == 0 || version == '0' || version == "unknown" || version == "Unknown" || version == "." ) return FALSE;

  if( isnull( icase ) ) icase = TRUE;
  if( icase ) {
    version = tolower( version );
    test_version = tolower( test_version );
  }

  if( debug ) display('DEBUG: Initial version: ' + version + ' and test_version: ' + test_version + '\n');

  # set / use a standard separator for the version and test_version parameter
  ver_sep = "."; # Set Standard Separator
  version = ereg_replace( pattern:"( |\-)", string:version, replace:"." );
  test_version = ereg_replace( pattern:"( |\-)", string:test_version, replace:"." );

  if( debug ) display('DEBUG: version: ' + version + ' and test_version: ' + test_version + ' after applying standard separator\n');

  # Some versions have e.g. 1.0.0g or 1.0.0beta1 so add a dot between them
  version = ereg_replace( pattern:"([0-9])([A-Za-z])", string:version, replace:"\1.\2" );
  test_version = ereg_replace( pattern:"([0-9])([A-Za-z])", string:test_version, replace:"\1.\2" );

  if( debug ) display('DEBUG: version: ' + version + ' and test_version: ' + test_version + ' after adding dots\n');

  # Split the versions into an array based on the ver_sep above
  ver_ary = split( version, sep:ver_sep, keep:FALSE );
  test_ary = split( test_version, sep:ver_sep, keep:FALSE );

  while( max_index( ver_ary ) < max_index( test_ary ) ) {
    ver_ary[max_index( ver_ary )] = "0";
  }

  while( max_index( ver_ary ) > max_index( test_ary ) ) {
    test_ary[max_index( test_ary )] = "0";
  }

  foreach i( keys( test_ary ) ) {

    r = eregmatch( pattern:"([0-9]+)", string:test_ary[i] );
    s = eregmatch( pattern:"([A-Za-z])", string:test_ary[i] );
    test_prerelease = eregmatch( pattern:"(rc|alpha|beta)([0-9]+)", string:test_ary[i], icase:TRUE );

    if( isnull( s ) ) {
      test_ary[i] = int( r[0] ) * 128; # Changed to * 128 so if a char follows a number the number is more significant
      char_found = FALSE;
    } else {
      if( isnull( test_prerelease ) ) {
        test_ary[i] = ( int( r[0] ) * 128 ) + ord( s[0] );
      } else {
        test_ary[i] = test_prerelease[2];
      }
      char_found = TRUE;
    }

    r = eregmatch( pattern:"([0-9]+)", string:ver_ary[i] );
    s = eregmatch( pattern:"([A-Za-z])", string:ver_ary[i] );
    ver_prerelease = eregmatch( pattern:"(rc|alpha|beta)([0-9]+)", string:ver_ary[i], icase:TRUE );

    if( isnull( s ) ) {
      ver_ary[i] = int( r[0] ) * 128;
    } else if( char_found ) {
      if( isnull( ver_prerelease ) ) {
        ver_ary[i] = ( int(r[0] ) * 128 ) + ord( s[0] );
      } else {
        ver_ary[i] = ver_prerelease[2];
      }
    } else {
      if( isnull( r ) ) {
        ver_ary[i] = ord( s[0] );
      } else {
        if( ! less ) return FALSE;      # If char found in test_version and no char in version it is not equal
        ver_ary[i] = int(r[0]) * 128;  # No chars if test_version has no chars on this position else 1.1.1a is > 1.1.2
      }
    }

    if( less ) {
      if( ver_ary[i] < test_ary[i] ) return TRUE;
      if( ver_ary[i] > test_ary[i] ) return FALSE;
    } else {
      if( ver_ary[i] != test_ary[i] ) return FALSE;
    }
  }
  if( less ) return FALSE;
  else return TRUE;
}

function version_is_less_equal( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_less_equal" );
  if( ! test_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_less_equal" );
  if( version_is_equal( version:version, test_version:test_version, icase:icase, debug:debug ) ) return TRUE;
  if( version_is_less( version:version, test_version:test_version, icase:icase, debug:debug ) ) return TRUE;
  return FALSE;
}

function version_is_greater_equal( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_greater_equal" );
  if( ! test_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_greater_equal" );
  if( version_is_equal( version:version, test_version:test_version, icase:icase, debug:debug ) ) return TRUE;
  if( version_is_less( version:test_version, test_version:version, icase:icase, debug:debug ) ) return TRUE;
  return FALSE;
}

function version_is_greater( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_greater" );
  if( ! test_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_greater" );
  if( version_is_less( version:test_version, test_version:version, icase:icase, debug:debug ) ) return TRUE;
  return FALSE;
}

function version_in_range( version, test_version, test_version2, icase, debug ) {

  local_var version, test_version, test_version2;

  if( ! version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_in_range" );
  if( ! test_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_in_range" );
  if( ! test_version2 ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version2#-#version_in_range" );
  if( version_is_greater_equal( version:version, test_version:test_version, icase:icase, debug:debug ) ) {
    if( version_is_less_equal( version:version, test_version:test_version2, icase:icase, debug:debug ) ) return TRUE;
  }
  return FALSE;
}

function get_version_from_kb( port, app ) {

  local_var port, app, vers, version, matches;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_version_from_kb" );
  if( ! app ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#app#-#get_version_from_kb" );

  if( isnull( port ) || isnull( app ) ) return FALSE;

  if( ! version = get_kb_item( "www/" + port + "/" + app ) ) return FALSE;
  if( ! matches = eregmatch( string:version, pattern:"^(.+) under (/.*)$" ) ) return FALSE;

  vers = matches[1];

  if( isnull( vers ) ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#vers#-#get_version_from_kb" );
    return FALSE;
  }

  if( vers == "unknown" || vers == "Unknown" ) return FALSE;

  return string( vers );
}

function get_dir_from_kb( port, app ) {

  local_var port, app, dir, version, matches;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_dir_from_kb" );
  if( ! app ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#app#-#get_dir_from_kb" );

  if( isnull( port ) || isnull( app ) ) return FALSE;

  if( ! version = get_kb_item( "www/" + port + "/" + app ) ) return FALSE;
  if( ! matches = eregmatch( string:version, pattern:"^(.+) under (/.*)$" ) ) return FALSE;

  dir = matches[2];

  if( isnull( dir ) ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dir#-#get_dir_from_kb" );
    return FALSE;
  }

  return string( dir );

}

# add  "script_dependencies("smb_nativelanman.nasl");" to your NVT to make this function work
function get_samba_version() {

  if( ! lanman = get_kb_item( "SMB/NativeLanManager" ) ) return FALSE;
  if( "Samba" >!< lanman ) return FALSE;

  if( ! version = eregmatch( pattern:"Samba ([0-9.]+)", string:lanman ) ) return FALSE;
  if( isnull( version[1] ) ) return FALSE;

  return version[1];
}

function check_locate( sock ) {

  local_var r;

  if( ! sock ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sock#-#check_locate" );

  if( get_kb_item( "no_linux_shell" ) ) return;
  if( get_kb_item( "lsc/locate/broken" ) ) return FALSE;

  if( ! get_kb_item( "lsc/locate/tested" ) ) {

    r = ssh_cmd( socket:sock, cmd:"locate -S", timeout:60 );

    if( ( "Database /" >!< r ||
        ( "bytes" >!< r &&
          "Compression" >!< r &&
          "Filenames"   >!< r &&
          "file names"  >!< r ) ) ||
          "command not found" >< r ||
          "locate:" >< r ) {

      set_kb_item( name:"lsc/locate/broken", value:TRUE );
      set_kb_item( name:"lsc/locate/tested", value:TRUE );
      return FALSE;
    }
    set_kb_item( name:"lsc/locate/tested", value:TRUE );
  }
  return TRUE;
}

## This function will return the version of the given file
function fetch_file_version( sysPath, file_name ) {

  local_var share, file, file_name, sysVer, kb_proxy_file, kb_proxy, kbsysPath ;
  # nb: Don't add sysPath to local_var as quite a lot LSCs are calling fetch_file_version(sysPath)

  if( ! sysPath )   set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sysPath#-#fetch_file_version" );
  if( ! file_name ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#fetch_file_version" );

  ## Query KB with specified file name first.
  ## Convert file name and sysPath to lower case.
  file_name = tolower( file_name );
  kbsysPath = tolower( sysPath ); # sysPath is currently not a local_var

  ## Construct KB string with file name.
  kb_proxy_file = "SMB//fetch_file_version//" + kbsysPath + "//" + file_name;

  ## Try to get the file version if already exists in KB
  kb_proxy = get_kb_item( kb_proxy_file );
  if( ! isnull( kb_proxy ) || kb_proxy ) {
    # Set to unknown to avoid that we're querying the version again if we already know that the file doesn't exist
    if( kb_proxy == "unknown" )
      return FALSE;
    else
      return kb_proxy;
  }

  share = ereg_replace( pattern:"([A-Za-z]):.*", replace:"\1$", string:sysPath );
  file =  ereg_replace( pattern:"[A-Za-z]:(.*)", replace:"\1", string:sysPath + "\" + file_name );

  # openvas-nasl-lint currently can't detect a missing function within a function
  if( ! defined_func( "GetVer" ) ) include( "secpod_smb_func.inc" );

  sysVer = GetVer( file:file, share:share );
  if( ! sysVer || isnull( sysVer ) || sysVer == "" || sysVer == 0 || sysVer == '0' ) {
    set_kb_item( name:kb_proxy_file, value:"unknown" );
    return FALSE;
  }

  ## set KB string with file name if its not exists already
  set_kb_item( name:kb_proxy_file, value:sysVer );

  return sysVer;
}

########################################################################
#
# Get the product version from file
#
########################################################################
function get_version( dllPath, string, offs ) {

  local_var name, login,  pass, domain,  port,  share, file, soc, r, prot, uid, tid, fid, prVersion;

  if( ! dllPath ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dllPath#-#get_version" );
    return FALSE;
  }

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  r = smb_session_request(soc:soc, remote:name);
  if(!r){
    close(soc);
    exit(0);
  }

  prot = smb_neg_prot(soc:soc);
  if(!prot){
    close(soc);
    exit(0);
  }

  r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
  if(!r){
    close(soc);
    exit(0);
  }

  uid = session_extract_uid(reply:r);
  if(!uid){
    close(soc);
    exit(0);
  }

  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  if(!r){
    close(soc);
    exit(0);
  }

  tid = tconx_extract_tid(reply:r);
  if(!tid){
    close(soc);
    exit(0);
  }

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid){
    close(soc);
    exit(0);
  }
      
  prVersion = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:string, offset:offs);
  if( ! prVersion || isnull( prVersion ) || prVersion == "" || prVersion == 0 || prVersion == '0' ) {
    close(soc);
    return FALSE;
  }

  close(soc);
  return prVersion;
}

function report_fixed_ver( installed_version, installed_build, installed_patch,
                           fixed_version, fixed_build, fixed_patch, extra ) {

  local_var installed_version, installed_build, installed_patch, fixed_version, fixed_build, fixed_patch, extra;

  if( ! installed_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#installed_version#-#report_fixed_ver" );
  if( ! fixed_version ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fixed_version#-#report_fixed_ver" );

  report = 'Installed version: ' + installed_version + '\n' +
           'Fixed version:     ' + fixed_version + '\n';

  if( installed_build ) report += 'Installed build:   ' + installed_build + '\n';
  if( installed_patch ) report += 'Installed patch:   ' + installed_patch + '\n';
  if( fixed_build ) report += 'Fixed build:       ' + fixed_build + '\n';
  if( fixed_patch ) report += 'Fixed patch:       ' + fixed_patch + '\n';
  if( extra ) report += '\n' + extra + '\n';

  return report;
}
