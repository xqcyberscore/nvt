###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_dep_remote_code_exec_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Microsoft Internet Explorer Remote Code Execution Vulnerability (979352)
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

tag_solution = "Apply the patch,
  http://support.microsoft.com/kb/979352

  Workaround:
  Apply workaround as in the advisory.

  *****
  NOTE: Ignore this warning if you are using IE 8 on Windows XP SP3 because
        IE 8 opts-in to DEP by default.
  *****";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  via specially crafted attack.
  Impact Level: Application";
tag_affected = "Internet Explorer Version 6.x, 7.x , 8.x";
tag_insight = "An invalid pointer reference error exists under certain conditions letting an
  invalid pointer to be accessed after an object is deleted.";
tag_summary = "The host is installed with Internet Explorer and is prone to Remote Code
  Execution vulnerability.

  This NVT has been replaced by NVT secpod_ms10-002.nasl
  (OID:1.3.6.1.4.1.25623.1.0.901097).";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800429");
  script_version("$Revision: 8457 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0249");
  script_bugtraq_id(37815);
  script_name("Microsoft Internet Explorer Remote Code Execution Vulnerability (979352)");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/979352");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/979352.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-002.nasl

include("smb_nt.inc");

ieVer = get_kb_item("MS/IE/Version");
if(isnull(ieVer)){
  exit(0);
}


# Checking For the workaround
if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion" +
                            "\AppCompatFlags\Custom\iexplore.exe")){
  exit(0);
}

#Checking for version
if(ieVer =~ "^[6|7|8]\."){
    security_message(0);
}
