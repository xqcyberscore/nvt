###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_reg_service_pack.nasl 11420 2018-09-17 06:33:13Z cfischer $
#
# SMB Registry : Windows Build Number and Service Pack Version
#
# Authors:
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#  Date Written: 2008/07/07
#  Revision: 1.5
#
#  Log: Modified by SecPod.
#  Issue #03 (By schandan)
#  Modified to support Win2K and Win2003 ServicePack Version.
#
#  Updated By: Antu Sanadi <santu@secpod.com> on 2010-08-20
#  - Enhanced the code to support Windows Vista Service packs.
#  - Enhaned the code to support Windows 7 service packs.
#  - Enhaned the code to support Windows server 2008.
#  - Updated to set the KB value to 0 if service pack is not
#  - installed and updated according to CR57. on 2012-03-27
#  - Enhaned the code to support Windows 8 32/64-bit service packs.
#  - Enhanced the code to support Windows Server 2012 64-bit Service packs.
#  - Enhanced the code to support Windows 10 32/64-bit Service packs.
#  - Enhanced the code to support Windows Server 2008 64-bit Service packs.
#  - Enhanced the code to support Windows Vista 64-bit Service packs.
#  - Enhanced the code to support Windows Server 2016 Service packs.
#
#  Updated By: Sooraj KS <kssooraj@secpod.com> on 2012-05-09
#  - Added 64-bit processor architecture check.
#  - Enhanced the code to support Windows 7 64-bit Service packs.
#  - Enhanced the code to support Windows XP 64-bit Service packs.
#  - Enhanced the code to support Windows 2003 64-bit Service packs.
#  - Enhanced the code to support Windows Server 2008 R2 Service packs.
#
# Copyright:
# Copyright (C) 2000 Renaud Deraison
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10401");
  script_version("$Revision: 11420 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-08-27 12:14:14 +0200 (Wed, 27 Aug 2008)");
  script_name("SMB Registry : Windows Build Number and Service Pack Version");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_copyright("This script is Copyright (C) 2000 Renaud Deraison");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency cycle.
  script_dependencies("smb_registry_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access");

  script_tag(name:"summary", value:"Detection of installed Windows build number and
  Service Pack version.

  The script logs in via SMB, and reads the registry key to retrieve
  Windows build number Service Pack Version and sets KnowledgeBase.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

SCRIPT_DESC = "SMB Registry : Windows Service Pack version";

access = get_kb_item( "SMB/registry_access");
if( ! access ) exit( 0 );

winVal = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentVersion" );
if( winVal ) set_kb_item( name:"SMB/WindowsVersion", value:winVal );

winBuild = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentBuild" );
if( winBuild ) set_kb_item( name:"SMB/WindowsBuild", value:winBuild );

winName = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"ProductName" );

if( winName ) {
  set_kb_item( name:"SMB/WindowsName", value:winName );
  os_str = winName;
  if( winVal ) os_str += ' ' + winVal;
  replace_kb_item( name:"Host/OS/smb", value:os_str );
  replace_kb_item( name:"SMB/OS", value:os_str );
}

csdVer = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CSDVersion" );
if( ! csdVer ) csdVer = "NO_Service_Pack";

key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if( ! registry_key_exists( key:key ) ) exit( 0 );

arch = registry_get_sz( key:key, item:"PROCESSOR_ARCHITECTURE" );
if( "64" >< arch ) {
  set_kb_item( name:"SMB/Windows/Arch", value:"x64" );
} else if( "x86" >< arch ) {
  set_kb_item( name:"SMB/Windows/Arch", value:"x86" );
} else {
  # nb: Sometimes there seems to be not enough permissions for that registry key to gather the
  # processor architecture so have a fallback for this case.
  if( ! arch ) {
    set_kb_item( name:"SMB/Windows/Arch", value:"unknown/failed to read PROCESSOR_ARCHITECTURE from key " + key );
  } else {
    set_kb_item( name:"SMB/Windows/Arch", value:arch );
  }
}

if( csdVer && "NO_Service_Pack" >!< csdVer ) {

  set_kb_item( name:"SMB/CSDVersion", value:csdVer );
  csdVer = eregmatch( pattern:"Service Pack [0-9]+", string:csdVer );
  if( ! isnull( csdVer[0] ) ) csdVer = csdVer[0];

  if( winVal == "4.0" ) {
    set_kb_item( name:"SMB/WinNT4/ServicePack", value:csdVer );
  }

  if( winVal == "5.0" && "Microsoft Windows 2000" >< winName ) {
    set_kb_item( name:"SMB/Win2K/ServicePack", value:csdVer );
  }

  if( winVal == "5.1" && "Microsoft Windows XP" >< winName ) {
    set_kb_item( name:"SMB/WinXP/ServicePack", value:csdVer );
  }

  if( winVal == "5.2" && "Microsoft Windows Server 2003" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win2003/ServicePack", value:csdVer );
  }

  if( winVal == "5.2" && "Microsoft Windows Server 2003" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2003x64/ServicePack", value:csdVer );
  }

  if( winVal == "5.2" && "Microsoft Windows XP" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/WinXPx64/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Vista" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/WinVista/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Vista" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/WinVistax64/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Server (R) 2008" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win2008/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Server (R) 2008" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2008x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.1" && "Windows 7" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win7/ServicePack", value:csdVer );
  }

  if( winVal == "6.1" && "Windows 7" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win7x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.1" && "Windows Server 2008 R2" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2008R2/ServicePack", value:csdVer );
  }

  if( winVal == "6.2" && "Windows Server 2012" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2012/ServicePack", value:csdVer );
  }

  if( winVal == "6.2" && "Windows 8" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win8/ServicePack", value:csdVer );
  }

  if( winVal == "6.2" && "Windows 8" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win8x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 8.1" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win8.1/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 8.1" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win8.1x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 10" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win10/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 10" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win10x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows Server 2012 R2" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2012R2/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows Server 2016" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2016/ServicePack", value:csdVer );
  }

  #nb: If updating / adding an OS here also update gb_windows_cpe_detect.nasl and gb_smb_windows_detect.nasl
}

if( ! isnull( os_str ) && ! isnull( csdVer ) && "NO_Service_Pack" >!< csdVer ) {
  report = os_str + " is installed with " + csdVer;
  log_message( port:0, data:report );
}

# At least Windows 10 don't have any Services Packs but just build numbers
else if( ! isnull( os_str ) && "Windows 10" >< winName && winBuild ) {
  set_kb_item( name:"SMB/Windows/ServicePack", value:"0" );
  report = os_str + " is installed with build number " + winBuild;
  log_message( port:0, data:report );
}

else if( ! isnull( os_str ) && ! isnull( csdVer ) && "NO_Service_Pack" >< csdVer ) {
  SP = "0";
  set_kb_item( name:"SMB/Windows/ServicePack", value:SP );
  report = os_str + " is installed with Service Pack " + SP;
  log_message( port:0, data:report );
}

exit( 0 );
