###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_mult_dos_vuln_win01.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# IBM DB2 Multiple DOS Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker bypass security restrictions,
  cause a denial of service or gain elevated privileges.
  Impact Level: System/Application";
tag_affected = "IBM DB2 version 8 prior to Fixpak 17
  IBM DB2 version 9.1 prior to Fixpak 7
  IBM DB2 version 9.5 prior to Fixpak 4";
tag_insight = "The flaws are due to,
  - An error in DRDA Services component that can be exploited via an IPv6 address
    in the correlation token in the APPID string.
  - An unspecified error can be exploited to connect to DB2 databases without
    a valid password if ldap-based authentication is used and the LDAP server
    allows anonymous binds.";
tag_solution = "Update DB2 8 Fixpak 17 or 9.1 Fixpak 7 or 9.5 Fixpak 4 or later.
  http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678";
tag_summary = "The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900673");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1905","CVE-2009-1906");
  script_bugtraq_id(35171);
  script_name("IBM DB2 Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35235");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50909");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IZ38874");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_mandatory_keys("Win/IBM-db2/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 Products Version 8 before 8 FP17 (8.1.17)-8.1.17.617
# Check for IBM DB2 Products Version 9.1 before 9.1 FP7 (9.1.700)-9.1.700.855
# Check for IBM DB2 Products Version 9.5 before 9.5 FP4 => 9.5.400.576
# IBM DB2 9.1 FP6a =>9.1.601.768
# IBM DB2 9.5 FP3b =>9.5.302.513

if(version_in_range(version:ibmVer, test_version:"8.0",
                    test_version2:"8.1.16")||
   version_in_range(version:ibmVer, test_version:"9.1",
                    test_version2:"9.1.601.768")||
   version_in_range(version:ibmVer, test_version:"9.5",
                    test_version2:"9.5.302.513")){
  security_message(0);
}
