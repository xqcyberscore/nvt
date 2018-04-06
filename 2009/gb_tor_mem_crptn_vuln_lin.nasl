###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_mem_crptn_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Tor Unspecified Remote Memory Corruption Vulnerability (Linux)
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

tag_impact = "A remote attcker can execute arbitrary code on the target system and
  can cause denial-of-service.

  Impact level: Application";

tag_affected = "Tor version prior to 0.2.0.33 on Linux.";
tag_insight = "Due to unknown impact, remote attachers can trigger heap corruption on
  the application.";
tag_solution = "Upgrade to version 0.2.0.33 or later
  https://www.torproject.org/download-unix.html.en";
tag_summary = "This host is installed with Tor and is prone to unspecified remote
  Memory Corruption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800350");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0414");
  script_bugtraq_id(33399);
  script_name("Tor Unspecified Remote Memory Corruption Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33635");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33677");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jan/1021633.html");
  script_xref(name : "URL" , value : "http://blog.torproject.org/blog/tor-0.2.0.33-stable-released");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_require_keys("Tor/Linux/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

torVer = get_kb_item("Tor/Linux/Ver");
if(torVer != NULL)
{
  # Grep for version prior to 0.2.0.33
  if(version_is_less(version:torVer, test_version:"0.2.0.33")){
    security_message(0);
  }
}
