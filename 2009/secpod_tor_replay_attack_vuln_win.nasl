###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_replay_attack_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Tor Replay Attack Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the remote attacker cause replay attacks
  in the network and can compromise router functionalities.

  Impact level: Network";

tag_affected = "Tor version 0.2.0.34 and prior on Windows.";
tag_insight = "Flaw is in the data flow at the end of the circuit which lets the attacker
  to modify the relayed data.";
tag_solution = "Upgrade to Tor version 0.2.1.25 or later,
  For updates refer to https://www.torproject.org";
tag_summary = "This host is installed with Tor Anonymity Proxy and is prone
  to replay attack vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900322");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0654");
  script_name("Tor Replay Attack Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://blog.torproject.org/blog/one-cell-enough");
  script_xref(name : "URL" , value : "http://www.blackhat.com/presentations/bh-dc-09/Fu/BlackHat-DC-09-Fu-Break-Tors-Anonymity.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_require_keys("Tor/Win/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(torVer != NULL)
{
  # Grep for version 0.2.0.34 and prior
  if(version_is_less_equal(version:torVer, test_version:"0.2.0.34")){
    security_message(0);
  }
}
