###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_neutering_xss_vuln.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Microsoft Internet Explorer 'neutering' Mechanism  XSS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to conduct
cross-site scripting (XSS) attacks on the affected system.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 8.x";

tag_insight = "The XSS filter in Internet Explorer does not perform neutering
for the SCRIPT tag which allows attackers to conduct cross-site scripting attacks.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Internet Explorer and is prone to
  cross-site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902166");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1489");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft Internet Explorer 'neutering' Mechanism XSS Vulnerability");
  script_xref(name : "URL" , value : "http://p42.us/ie8xss/");
  script_xref(name : "URL" , value : "http://p42.us/ie8xss/Abusing_IE8s_XSS_Filters.pdf");
  script_xref(name : "URL" , value : "http://blogs.technet.com/msrc/archive/2010/04/19/guidance-on-internet-explorer-xss-filter.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

# Check for Internet Explorer version
if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702")){
  security_message(0);
}
