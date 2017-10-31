###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_mult_sec_bypass_vuln.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# IBM DB2 Multiple Security Bypass Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attackers to bypass security
  restrictions.
  Impact Level: Application.";
tag_affected = "IBM DB2 versions prior to 9.7 Fix Pack 3";
tag_insight = "Multiple flaws are due to,
  - An error in the application while revoking privileges on a database object
    from the 'PUBLIC' group, which does not mark the dependent functions as
    'INVALID'.
  - An error in the application while compiling a compound SQL statement with
    an 'update' statement can be exploited by an unprivileged user to execute
    the query from the dynamic SQL cache.";
tag_solution = "Upgrade to IBM DB2 version 9.7 Fix Pack 3 or later,
  http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is running IBM DB2 and is prone to multiple security
  bypass vulnerabilities.";

if(description)
{
  script_id(901156);
  script_version("$Revision: 7585 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_bugtraq_id(43291);
  script_cve_id("CVE-2010-3474","CVE-2010-3475");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("IBM DB2 Multiple Security Bypass Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41444");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2425");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC68015");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC70406");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_require_keys("IBM-DB2/Remote/ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

## Check for IBM DB2 Versions Prior to 9.7 Fix Pack 3
## IBM DB2 9.7 FP 3 => 09073
if(version_is_less(version:ibmVer, test_version:"09073")){
  security_message(0);
}
