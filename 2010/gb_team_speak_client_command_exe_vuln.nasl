###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_team_speak_client_command_exe_vuln.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# TeamSpeak Client Arbitrary command execution vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code in
  the context of the user running the application.
  Impact Level: Application.";
tag_affected = "Teamspeak 2 version 2.0.32.60";

tag_insight = "The specific flaw exists within the 'TeamSpeak.exe' module, teardown procedure
  responsible for freeing dynamically allocated application handles.";
tag_solution = "Upgrade to the Teamspeak 3 or later
  For updates refer to http://www.tsviewer.com/index.php?page=teamspeak";
tag_summary = "This host is installed with TeamSpeak client and is prone to
  arbitrary command execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801537");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("TeamSpeak Client Arbitrary command execution vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Oct/439");
  script_xref(name : "URL" , value : "http://www.nsense.fi/advisories/nsense_2010_002.txt");
  script_xref(name : "URL" , value : "http://archives.free.net.ph/message/20101028.062014.2328daac.ja.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## check application installation
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  tsName = registry_get_sz(key:key + item, item:"DisplayName");
  if("TeamSpeak 2" >< tsName)
  {
    tsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(tsVer != NULL)
    {
      ## Check version is equal 2.0.32.60
      if(version_is_equal(version:tsVer, test_version:"2.0.32.60"))
      {
        security_message(0) ;
        exit(0);
      }
    }
  }
}
