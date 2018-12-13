###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emotet_trojan_detect.nasl 12788 2018-12-13 12:26:25Z cfischer $
#
# Emotet Trojan Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108521");
  script_version("$Revision: 12788 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-13 13:26:25 +0100 (Thu, 13 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-13 07:34:56 +0100 (Thu, 13 Dec 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"10.0");
  script_name("Emotet Trojan Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Malware");
  script_dependencies("gb_wmi_access.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/alerts/TA18-201A");
  script_xref(name:"URL", value:"https://blog.malwarebytes.com/detections/trojan-emotet/");
  script_xref(name:"URL", value:"https://www.barkly.com/emotet-trojan-removal-prevention");

  script_add_preference(name:"Run check", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"The script tries to detect the Emotet Trojan via various known Indicators of Compromise (IOC).

  Note: This script is not running by default as it needs to crawl the target host for various files which puts high
  load on the target during the scan. Please enable it separately within scripts preference.");

  script_tag(name:"impact", value:"Trojan.Emotet is a Trojan horse that may steal sensitive data, open a back door on the
  compromised computer or download potentially malicious files.");

  script_tag(name:"affected", value:"All Windows Systems.");

  script_tag(name:"solution", value:"A whole cleanup of the infected system is recommended.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");

  script_timeout(600);

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("wmi_file.inc");

run_check = script_get_preference( "Run check" );
if( ! run_check || "yes" >!< run_check )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

glob_ioc = 0;
tool_ioc = 0;
ioc_list = make_list();

# Those are legitimate tools used by the Trojan, if all three exists
# on the target we're counting it as one IoC.
foreach tools_file( make_list( "NetPass.exe", "WebBrowserPassView.exe", "mailpv.exe" ) ) {

  split_file = split( tools_file, sep:".", keep:FALSE );
  if( max_index( split_file ) != 2 )
    continue;

  file_name = split_file[0];
  file_extn = split_file[1];

  files_list = wmi_file_file_search( handle:handle, fileName:file_name, fileExtn:file_extn, includeHeader:FALSE );
  if( ! files_list || ! is_array( files_list ) )
    continue;

  # Make sure that we haven't found the same file multiple times
  # to only count each file once to avoid e.g. that NetPass.exe
  # was downloaded by a user multiple times on purpose.
  foreach found( files_list ) {
    if( ! in_array( search:found, array:ioc_list, part_match:TRUE ) ) {
      tool_ioc++;
      ioc_list = make_list( ioc_list, found );
    }
  }
}

if( tool_ioc > 2 )
  glob_ioc++;

# Some sample files found on various sources. We're out of luck from NASL side to detect the random files generated
# by the Trojan so we're trying our best to detect the ones we know.

# C:\Windows\System32\shedaudio.exe
# C:\Windows\SysWOW64\servicedcom.exe
# C:\WINDOWS\SYSWOW64\SERVERNV.EXE
# C:\Windows\SysWOW64\svcapp.exe
# C:\Users\<username>\AppData\Local\Microsoft\Windows\shedaudio.exe
foreach sys_file( make_list( "svcapp.exe", "shedaudio.exe", "servicedcom.exe", "servernv.exe", "46615275.exe", "f9jwqSbS.exe", "searchhost.exe", "cachewlan.exe" ) ) {

  split_file = split( sys_file, sep:".", keep:FALSE );
  if( max_index( split_file ) != 2 )
    continue;

  file_name = split_file[0];
  file_extn = split_file[1];

  foreach path( make_list( "\\Windows\\System32\\", "\\Windows\\SysWOW64\\", "\\Users\\" ) ) {

    files_list = wmi_file_file_search( handle:handle, dirPath:path, fileName:file_name, fileExtn:file_extn, includeHeader:FALSE );
    if( files_list && is_array( files_list ) ) {
      foreach found( files_list ) {
        if( ! in_array( search:found, array:ioc_list, part_match:TRUE ) ) {
          glob_ioc++;
          ioc_list = make_list( ioc_list, found );
        }
      }
    }
  }
}

foreach glob_file( make_list( "loaddll.exe", "PlayingonaHash.exe", "certapp.exe", "CleanToast.exe", "CciAllow.exe", "RulerRuler.exe", "connectmrm.exe") ) {

  split_file = split( glob_file, sep:".", keep:FALSE );
  if( max_index( split_file ) != 2 )
    continue;

  file_name = split_file[0];
  file_extn = split_file[1];

  files_list = wmi_file_file_search( handle:handle, fileName:file_name, fileExtn:file_extn, includeHeader:FALSE );
  if( ! files_list || ! is_array( files_list ) )
    continue;

  foreach found( files_list ) {
    if( ! in_array( search:found, array:ioc_list, part_match:TRUE ) ) {
      glob_ioc++;
      ioc_list = make_list( ioc_list, found );
    }
  }
}

wmi_close( wmi_handle:handle );

# nb: We only have the "Author" info in the registry on Windows 10 and similar but not in Windows 7..
winVer = get_kb_item( "SMB/WindowsVersion" );
if( winVer && winVer >= "6.3" ) {

  # The deployed scheduled task often has no Publisher/Author set, using this as an IoC.
  # nb: We can't use Win32_ScheduledJob as this isn't listening such tasks.
  key  = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\";
  key2 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\";
  foreach item( registry_enum_keys( key:key ) ) {
    id = registry_get_sz( key:key + item, item:"Id" );
    if( ! id || id[0] != "{" )

    author = registry_get_sz( key:key2 + id, item:"Author" );
    if( author ) {
      glob_ioc++;
      ioc_list = make_list( ioc_list, key2 + id );
      # nb: Some valid schedules like "GoogleUpdateTaskMachineCore" don't have an "Author" set
      # so we're counting only the first scheduled task without an author as an IoC.
      break;
    }
  }
}

# e.g. CurrentVersion\Run {Random Names} with value c:\users\admin\appdata\roaming\{Random}{Legitimate Filename}.exe
run_ioc = 0;
foreach key( make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" ) ) {
  foreach item( registry_enum_values( key:key ) ) {
    path = registry_get_sz( key:key, item:item );
    if( path && path =~ "\\users\\.+\\appdata\\(roaming|local)\\.+\.exe" ) {
      run_ioc++;
      glob_ioc++;
      ioc_list = make_list( ioc_list, "HKEY_LOCAL_MACHINE\" + key + "\" +  item + ":" + path );
      # nb: Only count the first of such an existing run key as one single IoC.
      break;
    }
  }
  if( run_ioc > 0 )
    break;
}

if( ! run_ioc ) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
  foreach item( registry_enum_values( key:key, type:"HKCU" ) ) {
    path = registry_get_sz( key:key, item:item, type:"HKCU" );
    if( path && path =~ "\\users\\.+\\appdata\\(roaming|local)\\.+\.exe" ) {
      glob_ioc++;
      ioc_list = make_list( ioc_list, "HKEY_CURRENT_USER\" + key + "\" +  item + ":" + path );
      # nb: Only count the first of such an existing run key as one single IoC.
      break;
    }
  }
}

if( glob_ioc > 2 ) {
  report  = "The Emotet Trojan has been found based on the following IoCs:";
  report += '\n\nFilename/Registry-Key\n';
  foreach ioc( ioc_list ) {
    report += ioc + '\n';
  }
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );