###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_dbadm_sec_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM DB2 DBADM Privilege Revocation Security Bypass Vulnerability
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

tag_impact = "Successful exploitation allows remote authenticated users to
  execute non-DDL statements by leveraging previous possession of this
  authority.
  Impact Level: Application.";
tag_affected = "IBM DB2 version 9.1 before FP10,
  IBM DB2 version 9.5 before FP6a and
  IBM DB2 version 9.7 before FP2";
tag_insight = "The flaw is due to an error in the application while revoking
  'DBADM' privileges. This does not restrict users from executing
  non-DDL statements.";
tag_solution = "Upgrade to IBM DB2 version 9.1 FP10, 9.5 FP6a, 9.7 FP2 or later,
  http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is running IBM DB2 and is prone to security bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801588");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46064);
  script_cve_id("CVE-2011-0757");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("IBM DB2 DBADM Privilege Revocation Security Bypass Vulnerability");


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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43148");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65008");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg21426108");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg1IC66814");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg1IC66814&crawler=1");
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 2 => 09072
  if(version_is_less(version:ibmVer, test_version:"09072"))
  {
    security_message(0);
    exit(0);
  }
}

if(ibmVer =~ "^0901\.*")
{
  # IBM DB2 9.1 FP 10 => 090110
  if(version_is_less(version:ibmVer, test_version:"090110"))
  {
    security_message(0);
    exit(0);
  }
}

if(ibmVer =~ "^0905\.*")
{
  # IBM DB2 9.5 FP 6 => 09056
  if(version_is_less(version:ibmVer, test_version:"09056")){
    security_message(0);
  }
}

