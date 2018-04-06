###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_location_hash_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer 'location.hash' DOS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation lets the attacker cause memory or CPU
consumption, resulting in Denial of Service condition.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 6.0.2900.2180 and prior.";

tag_insight = "Error exists when application fails to handle JavaScript code
with a long string value for the hash property aka 'location.hash'.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Internet Explorer and is prone to
Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900826");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2954");
  script_name("Microsoft Internet Explorer 'location.hash' DOS Vulnerability");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3424/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/506006/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for Microsoft Internet Explorer version <= 6.0.2900.2180
if(version_is_less_equal(version:ieVer, test_version:"6.0.2900.2180")){
  security_message(0);
}
