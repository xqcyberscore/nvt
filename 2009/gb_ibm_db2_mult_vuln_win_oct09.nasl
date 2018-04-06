###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_mult_vuln_win_oct09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# IBM DB2 Multiple Vulnerabilities - Oct09 (Windows)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Unknown impact.

  Impact Level: System/Application";
tag_affected = "IBM DB2 version 8 prior to Fixpak 18
  IBM DB2 version 9.1 prior to Fixpak 8
  IBM DB2 version 9.5 prior to Fixpak 4";
tag_insight = "- An unspecified error exists related to a table function when the definer
    loses required privileges.
  - An unspecified error can be exploited to insert, update, or delete rows in
    a table without having required privileges.";
tag_solution = "Update DB2 8 Fixpak 18 or 9.1 Fixpak 8 or 9.5 Fixpak 4 or later.
  http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801009");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3471", "CVE-2009-3472");
  script_bugtraq_id(36540);
  script_name("IBM DB2 Multiple Vulnerabilities - Oct09 (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36890");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21403619");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21386689");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_require_keys("Win/IBM-db2/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 version 8 before FP18, 9.1 before FP8, 9.5 before FP4
# 9.1 FP8 => 9.1.800.1023, 9.5 FP4 => 9.5.400.576, 8 FP18 =>8.1.18
if(version_in_range(version:ibmVer, test_version:"8.0", test_version2:"8.1.17")||
   version_in_range(version:ibmVer, test_version:"9.1", test_version2:"9.1.800.1022")||
   version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.400.575")){
  security_message(0);
}
