###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_strongswan_mult_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# strongSwan IKE_SA_INIT and IKE_AUTH DoS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Upgrade to version 4.3.1 or 4.2.15 or apply patches
  http://download.strongswan.org/patches/
  http://www.strongswan.org/download.htm

  *****
  NOTE: Ignore this warning, if above mentioned Update is applied already.
  *****";

tag_impact = "Successful exploit allows attackers to run arbitrary code, corrupt memory,
  and can cause denial of service.
  Impact Level: Application";
tag_affected = "strongSwan Version prior to 4.2.15 and 4.3.1";
tag_insight = "The flaws are due to,
  - An error in charon/sa/ike_sa.c charon daemon which results in NULL pointer
    dereference and crash via an invalid 'IKE_SA_INIT' request that triggers
   'an incomplete state,' followed by a 'CREATE_CHILD_SA' request.
  - An error in incharon/sa/tasks/child_create.c charon daemon, it switches
    the NULL checks for TSi and TSr payloads, via an 'IKE_AUTH' request without
    a 'TSi' or 'TSr' traffic selector.";
tag_summary = "This host has installed strongSwan and is prone to Denial of Service
  Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800632");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1957", "CVE-2009-1958");
  script_bugtraq_id(35178);
  script_name("strongSwan IKE_SA_INIT and IKE_AUTH DoS Vulnerabilities");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1476");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/06/06/9");
  script_xref(name : "URL" , value : "https://lists.strongswan.org/pipermail/users/2009-May/003457.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_strongswan_detect.nasl");
  script_require_keys("StrongSwan/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

strongswanVer = get_kb_item("StrongSwan/Ver");

# Check version 4.1.0 to 4.3.0 and Except 4.2.15
if(strongswanVer != NULL && strongswanVer != "4.2.15")
{
  if(version_in_range(version:strongswanVer, test_version:"4.1.0",
                                             test_version2:"4.3.0")){
    security_message(0);
  }
}
