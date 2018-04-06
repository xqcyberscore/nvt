###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gizmo5_ssl_certi_sec_bypass_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Gizmo5 SSL Certificate Validation Security Bypass Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to obtain
sensitive information that could be used to launch further attacks against the
victim's system.

Impact Level: System/Application";

tag_affected = "Gizmo5 version 3.1.0.79 and prior on Linux";

tag_insight = "Error exists due to improper verification of SSL certificates
which can be exploited by using man-in-the-middle techniques to spoof SSL
certificates and redirect a user to a malicious Web site that would appear to
be trusted.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Gizmo5 and is prone to Security Bypass
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800833");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2381");
  script_bugtraq_id(35508);
  script_name("Gizmo5 SSL Certificate Validation Security Bypass Vulnerability (Linux) ");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35628");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51399");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504572/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gizmo5_detect_lin.nasl");
  script_require_keys("Gizmo5/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

foreach gizmoPort (make_list(5004, 5005))
{
  if(get_udp_port_state(gizmoPort))
  {
    gizmoVer = get_kb_item("Gizmo5/Linux/Ver");
    if(gizmoVer == NULL){
      exit(0);
    }

    if(version_is_less_equal(version:gizmoVer, test_version:"3.1.0.79")){
      security_message(port:gizmoPort, proto:"udp");
    }
  }
}
