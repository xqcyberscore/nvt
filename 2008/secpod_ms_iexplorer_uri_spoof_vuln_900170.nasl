##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iexplorer_uri_spoof_vuln_900170.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Microsoft iExplorer '&NBSP;' Address Bar URI Spoofing Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
##############################################################################

tag_summary = "This host is installed with Microsoft Internet Explorer and is prone
  to an URI spoofing vulnerability.";

tag_insight = "The flaw exists due to inadequately handling specific combinations
  of non-breaking space characters like '&NBSP;'.";

tag_impact = "An attacker may leverage this issue to spoof the source URI of a site which leads
  to false sense of trust.

  Impact Level: System";
tag_affected = "Microsoft Internet Explorer versions 6.0 SP1 and prior";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.
For updates refer to http://windows.microsoft.com/en-us/internet-explorer/download-ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900170");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)");
  script_bugtraq_id(31960);
  script_cve_id("CVE-2008-4787");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Microsoft iExplorer '&NBSP;' Address Bar URI Spoofing Vulnerability");

  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight", value: tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Internet Explorer";
iExpVer = registry_get_sz(key:key , item:"Version");
if(!iExpVer){
  iExpVer = registry_get_sz(key:key, item:"W2kVersion");
  if(!iExpVer){
    exit(0);
  }
}

# Grep for version 6.0 x
if(ereg(pattern:"^6\.0", string:iExpVer)){
  security_message(0);
}
