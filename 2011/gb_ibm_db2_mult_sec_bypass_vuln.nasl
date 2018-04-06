###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_mult_sec_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM DB2 Multiple Security Bypass Vulnerabilities (May-11)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to bypass security restrictions,
  gain knowledge of sensitive information or cause a denial of service.
  Impact Level: Application.";
tag_affected = "IBM DB2 versions prior to 9.5 Fix Pack 7
  IBM DB2 versions prior to 9.7 Fix Pack 4";
tag_insight = "Multiple flaws are due to,
  - An access validation error which could allow users to update statistics for
    tables without appropriate privileges.
  - An error when revoking role memberships, which could result in a user
    continuing to have privileges to execute a non-DDL statement after role
    membership has been revoked from its group.";
tag_solution = "Update DB2 to 9.5 Fix Pack 7, or 9.7 Fix Pack 4,
  For updates refer to http://www.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is running IBM DB2 and is prone to multiple security bypass
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801930");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1846", "CVE-2011-1847");
  script_bugtraq_id(47525);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("IBM DB2 Multiple Security Bypass Vulnerabilities (May-11)");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_require_keys("IBM-DB2/Remote/ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44229");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66980");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1083");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg1IC71263&crawler=1");
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 4 => 09074
  if(version_is_less(version:ibmVer, test_version:"09074"))
  {
    security_message(0);
    exit(0);
  }
}

if(ibmVer =~ "^0905\.*")
{
  # IBM DB2 9.5 FP 7 => 09057
  if(version_is_less(version:ibmVer, test_version:"09057")){
    security_message(0);
  }
}
