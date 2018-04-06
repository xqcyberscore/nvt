###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zim_server_mult_vuln_800201.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# ZIM Server Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_impact = "Successful exploitation could result in remote arbitrary code execution and
  cause denial of service.
  Impact Level: System";
tag_affected = "Zilab Software Zilab Chat and Instant Messaging Server 2.1 and prior.";
tag_insight = "The issues are due to,
  - boundary errors in the server while handling overly long crafted packets
    sent to default prot 7700.
  - a null pointer de-reference within the server will crash the service via
    a specially crafted packet sent to default port 7700.";
tag_solution = "Upgrde to Zilab Software Zilab Chat and Instant Messaging Server version 3.3 or later
  For updates refer to http://www.zilab.com/zim.shtml.";
tag_summary = "The host is installed with ZIM Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800201");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-03 15:02:49 +0100 (Wed, 03 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5279", "CVE-2008-5280");
  script_bugtraq_id(27940);
  script_name("ZIM Server Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/zilabzcsx-adv.txt");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/363848.php");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29062");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

entries = registry_enum_keys(key:key);
foreach item (entries)
{
  ver = registry_get_sz(key:key + item, item:"DisplayName");
  if("Zim" >< ver)
  {
    zimVer = eregmatch(pattern:"Zim v([0-9.]+)", string:ver);
    if(zimVer[1] != NULL)
    {
      # Grep for version <= 2.1
      if(version_is_less_equal(version:zimVer[1], test_version:"2.1")){
        security_message(0);
      }
    }
    exit(0);
  }
}
