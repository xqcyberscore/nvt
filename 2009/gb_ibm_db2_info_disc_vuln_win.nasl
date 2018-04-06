###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_info_disc_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# IBM DB2 Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Apply the security update.
  http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678

  *****
  NOTE: Please, ignore the warning if Patch is already applied.
  *****";

tag_impact = "Successful exploitation will let the attacker gain sensitive information of
  the affected remote system.
  Impact Level: Application";
tag_affected = "IBM DB2 Enterprise Server 9.1 before 9.1 FP7.
  IBM DB2 Workgroup Server 9.1 before 9.1 FP7.
  IBM DB2 Express Server 9.1 before 9.1 FP7.
  IBM DB2 Personal Server 9.1 before 9.1 FP7.
  IBM DB2 Connect Server 9.1 before 9.1 FP7.";
tag_insight = "This flaw is due to the 'INNER JOIN' and 'OUTER JOIN' predicate which allows
  remote attackers to execute arbitrary queries.";
tag_summary = "This host is installed with IBM DB2 and is prone to Information
  Disclosure Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800702");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1239");
  script_bugtraq_id(34650);
  script_name("IBM DB2 Information Disclosure Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49864");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0912");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21381257");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_require_keys("Win/IBM-db2/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

appVer = get_kb_item("Win/IBM-db2/Ver");
if(appVer == NULL){
  exit(0);
}

# Check for IBM DB2 Server Products Version 9.1 before 9.1 FP7 (9.1.700.855)
# version 9.1 FP6a => 9.1.601.768
if(version_in_range(version:appVer, test_version:"9.1", test_version2:"9.1.601.768")){
  security_message(0);
}
