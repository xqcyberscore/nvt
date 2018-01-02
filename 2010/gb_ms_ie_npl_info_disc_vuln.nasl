###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_npl_info_disc_vuln.nasl 8254 2017-12-28 07:29:05Z teissa $
#
# Microsoft Internet Explorer Information Disclosure Vulnerability (980088)
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

tag_solution = "Apply the patch from below link,
  http://support.microsoft.com/kb/980088

  Workaround:
  Apply workaround as in the advisory.";

tag_impact = "Successful exploitation will allow remote attackers to gain knowledge of
  sensitive information.
  Impact Level:System/ Application";
tag_affected = "Internet Explorer Version 5.x, 6.x, 7.x , 8.x";
tag_insight = "The issue is due to the browser failing to prevent local content from
  being rendered as HTML via the 'file://' protocol, which could allow attackers
  to access files with an already known filename and location on a vulnerable
  system.";
tag_summary = "The host is installed with Internet Explorer and is prone to Information
  Disclosure vulnerability.

  This NVT has been replaced by NVT secpod_ms10-035.nasl (OID:1.3.6.1.4.1.25623.1.0.902191).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800461");
  script_version("$Revision: 8254 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 08:29:05 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0255");
  script_bugtraq_id(38055, 38056);
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (980088)");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/980088");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0291");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/980088.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
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


exit(66); ## This NVT is deprecated as addressed in secpod_ms10-035.nasl

include("smb_nt.inc");

ieVer = get_kb_item("MS/IE/Version");
if(isnull(ieVer)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\Internet Settings\RestrictedProtocols"))
{
  #Check for workaround
  value = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                          "\Internet Settings\RestrictedProtocols\1", item:"file");
  if("file" >!<  value)
  {
    #check for workaround
    pValue = registry_get_dword(key:"SOFTWARE\Microsoft\Internet Explorer\Main" +
                         "\FeatureControl\FEATURE_PROTOCOL_LOCKDOWN", item:"explorer.exe");
    if(pValue != "1" && (pValue == 0))
    {
      #Check for version
      if(ieVer =~ "^[5|6|7|8]\."){
        security_message(0);
      }
    }
  }
}
