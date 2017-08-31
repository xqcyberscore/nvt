###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_66554.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# Ecava IntegraXor Account Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103934";

tag_impact = "Attackers can exploit this issue to obtain sensitive information that
may lead to further attacks.";

tag_affected = "Versions prior to IntegraXor 4.1.4393 are vulnerable.";
tag_summary = "Ecava IntegraXor is prone to an information-disclosure vulnerability.";
tag_solution = "Updates are available.";
tag_vuldetect = "Check the version";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(66554);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 6637 $");

 script_name("Ecava IntegraXor Account Information Disclosure Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66554");
 script_xref(name:"URL", value:"http://www.integraxor.com/");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-04-03 13:12:18 +0200 (Thu, 03 Apr 2014)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"registry");
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ecavaigName = registry_get_sz(key:key + item, item:"DisplayName");

  if("IntegraXor" >< ecavaigName)
  {
    ecavaigVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ecavaigVer != NULL)
    {
      if(version_is_less(version:ecavaigVer, test_version:"4.1.4393"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

