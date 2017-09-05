###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-029.nasl 7051 2017-09-04 11:38:56Z cfischer $
#
# Microsoft GDI+ Remote Code Execution Vulnerability (2489979)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902365");
  script_version("$Revision: 7051 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:38:56 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0041");
  script_bugtraq_id(47250);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft GDI+ Remote Code Execution Vulnerability (2489979)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38510/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0946");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-029");

  tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code
  via a specially crafted web page.

  Impact Level: System";

  tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";

  tag_insight = "The flaw is caused by an integer overflow error in the GDI+ library when
  processing malformed data.";

  tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-029.mspx";

  tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-029.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

## Check for OS and Service Pack
if( hotfix_check_sp( xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win2008:3 ) <= 0 ) exit( 0 );

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );
if( ! host || ! usrname || ! passwd ) exit( 0 );
domain  = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'gdiplus' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'dll' + raw_string(0x22);
fileVer = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );
if( ! fileVer ) exit( 0 );

foreach ver( split( fileVer ) ) {

  ver = eregmatch(pattern:"\gdiplus.dll.?([0-9.]+)", string:ver);
  if( ver[1] ) {
    ## Windows XP
    if( hotfix_check_sp( xp:4 ) > 0 ) {
      ## Check for Gdiplus.dll version before 5.2.6002.22509
      if( version_is_greater_equal( version:ver[1], test_version:"5.2.6002.22509" ) ) {
         flag = TRUE;
         break;
      }
    }

    ## Windows 2003
    else if( hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3 ) > 0 ) {
      ## Check for Gdiplus.dll version before 5.2.6002.22507
      if( version_is_greater_equal( version:ver[1], test_version:"5.2.6002.22507" ) ) {
        flag = TRUE;
        break;
      }
    }

    ## Windows Vista and 2008 server
    else if( hotfix_check_sp( winVista:3, win2008:3 ) > 0 ) {
      SP = get_kb_item( "SMB/WinVista/ServicePack" );
      if( ! SP ) {
        SP = get_kb_item( "SMB/Win2008/ServicePack" );
      }

      if( "Service Pack 1" >< SP ) {
        ## Check for Gdiplus.dll version
        if( version_in_range( version:ver[1], test_version:"5.2.6001.18551", test_version2:"5.2.6001.21999" ) ||
            version_is_greater_equal( version:ver[1], test_version:"5.2.6001.22791" ) ||
            version_in_range( version:ver[1], test_version:"6.0.6001.18551", test_version2:"6.0.6001.21999" ) ||
            version_is_greater_equal( version:ver[1], test_version:"6.0.6001.22791" ) ) {
          flag = TRUE;
          break;
        }
      }

      if( "Service Pack 2" >< SP ) {
        ## Check for Gdiplus.dll version
        if( version_in_range( version:ver[1], test_version:"5.2.6002.18342", test_version2:"5.2.6002.21999" ) ||
            version_is_greater_equal( version:ver[1], test_version:"5.2.6002.22519" ) ||
            version_in_range( version:ver[1], test_version:"6.0.6002.18342", test_version2:"6.0.6002.21999" ) ||
            version_is_greater_equal( version:ver[1], test_version:"6.0.6002.22519" ) ) {
          flag = TRUE;
          break;
        }
      }
    }
  }
}

if( ! flag ) {
  security_message( port:0 );
  exit( 0 );
}

exit( 99 );