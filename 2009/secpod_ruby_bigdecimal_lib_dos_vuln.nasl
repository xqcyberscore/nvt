###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_bigdecimal_lib_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Ruby BigDecimal Library Denial of Service Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Attackers can exploit this issue to crash an application using this library.
  Impact Level: Application";
tag_affected = "Ruby 1.8.6 to 1.8.6-p368 and 1.8.7 to 1.8.7-p172 on Linux.";
tag_insight = "The flaw is due to an error within the BigDecimal standard library
  when trying to convert BigDecimal objects into floating point numbers
  which leads to segmentation fault.";
tag_solution = "Upgrade to 1.8.6-p369 or 1.8.7-p174.
  http://www.ruby-lang.org/en/news/2009/06/09/dos-vulnerability-in-bigdecimal/";
tag_summary = "The host is installed with Ruby and is prone to denial of
  service  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900570");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1904");
  script_bugtraq_id(35278);
  script_name("Ruby BigDecimal Library Denial of Service Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34135");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/linux/964");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ruby_detect_lin.nasl");
  script_require_keys("Ruby/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

if(!rubyVer){
  exit(0);
}

if(version_in_range(version:rubyVer, test_version:"1.8.6", test_version2:"1.8.6.p367")||
   version_in_range(version:rubyVer, test_version:"1.8.7", test_version2:"1.8.7.p172")){
  security_message(0);
rubyVer = get_kb_item("Ruby/Lin/Ver");
}
