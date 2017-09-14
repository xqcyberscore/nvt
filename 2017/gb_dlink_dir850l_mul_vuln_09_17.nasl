###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir850l_mul_vuln_09_17.nasl 7116 2017-09-13 09:13:25Z teissa $
#
# D-Link 850L XSS / Backdoor / Code Execution Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107242");
  script_version("$Revision: 7116 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-13 11:13:25 +0200 (Wed, 13 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-12 17:47:21 +0200 (Tue, 12 Sep 2017)");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("D-Link 850L XSS / Backdoor / Code Execution Vulnerabilities");

  script_tag(name: "summary", value: "D-Link 850L suffers from cross site scripting, access bypass, backdoor, bruteforcing, information disclosure, remote code execution, and denial of service vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "The Dlink 850L is a router overall badly designed with a lot of vulnerabilities . Everything can be pwned, from the LAN to the WAN.");
  script_tag(name: "impact" , value: "Remote attacker can execute xss attacks, gain admin password, forge firmware and many other attacks.");
  script_tag(name: "affected", value: "DLink Dir 850 L Rev A1 and B1");

  script_tag(name: "solution", value: "No solution is available until 12 September 2017, it is recommended to stop using this product immediately.");

  script_xref(name: "URL" , value: "https://packetstormsecurity.com/files/144056/dlink850l-xssexecxsrf.txt");
  script_xref(name: "URL" , value: "http://securityaffairs.co/wordpress/62937/hacking/d-link-dir-850l-zero-day.html");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("host_is_dlink_dir", "dlink_hw_version");

  exit(0);
}

include("version_func.inc");

if(!Port = get_kb_item("dlink_dir_port")){
  exit(0);
}

if (!type = get_kb_item("dlink_typ")){
  exit(0);
}

if (!hw_version = get_kb_item("dlink_hw_version")){
  exit(0);
}

if (!version = get_kb_item("dlink_fw_version")){
  exit(0);
}

if (type == "DIR-850L" && (hw_version == "A1" || hw_version == "B1"))
{
  report =  report_fixed_ver(installed_version:version, fixed_version:"Non Available");
  security_message(data:report);
  exit( 0 );
}

exit ( 99 );

