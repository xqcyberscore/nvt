###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_sysibmadm_mult_vuln_sep10.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# IBM DB2 SYSIBMADM Multiple Vulnerabilities (Sep10)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  restrictions, gain knowledge of sensitive information or cause a denial
  of service.
  Impact Level: Application.";
tag_affected = "IBM DB2 versions prior to 9.7 Fix Pack 2";
tag_insight = "Multiple flaws are due to,
  - An erron in the handling of 'SYSIBMADM' schema. It does not perform the
    expected access control on the monitor administrative, which allows
    attackers to obtain sensitive information via unspecified vectors.
  - An erron in the handling of 'AUTO_REVAL' when AUTO_REVAL is IMMEDIATE,
    which allows remote authenticated users to cause a denial of service.";
tag_solution = "Update DB2 version 9.7 Fix Pack 2,
  http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is running IBM DB2 and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801504");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_cve_id("CVE-2010-3196", "CVE-2010-3197");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IBM DB2 SYSIBMADM Multiple Vulnerabilities (Sep10)");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC67008");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21432298");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC67819");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 2 => 09072
  if(version_is_less(version:ibmVer, test_version:"09072")){
    security_message(0);
  }
}
