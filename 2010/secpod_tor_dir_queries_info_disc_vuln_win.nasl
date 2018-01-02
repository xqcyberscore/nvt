###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_dir_queries_info_disc_vuln_win.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# Tor Directory Queries Information Disclosure Vulnerability (win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attackers to obtain sensitive information
  that can help them launch further attacks.

  Impact level: Application";

tag_affected = "Tor version prior to 0.2.1.22 and 0.2.2.x before 0.2.2.7-alpha on Windows.";
tag_insight = "The issue is due to bridge directory authorities disclosing all tracked
  bridge identities when responding to 'dbg-stability.txt' directory queries.";
tag_solution = "Upgrade to version 0.2.1.22 or later
  http://www.torproject.org/download.html.en";
tag_summary = "This host is installed with Tor and is prone to Information Disclosure
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901100");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0383", "CVE-2010-0385");
  script_bugtraq_id(37901);
  script_name("Tor Directory Queries Information Disclosure Vulnerability (win)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38198");
  script_xref(name : "URL" , value : "http://archives.seul.org/or/talk/Jan-2010/msg00162.html");
  script_xref(name : "URL" , value : "http://archives.seul.org/or/announce/Jan-2010/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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


include("http_func.inc");
include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(torVer == NULL){
  exit(0);
}


foreach torPort (make_list(9050, 9051, 8118))
{
  if(get_port_state(torPort))
  {
    sndReq = string("GET / HTTP/1.1", "\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");
    rcvRes = http_send_recv(port:torPort, data:sndReq);

    if(!isnull(rcvRes) && "Tor is" >< rcvRes)
    {
      torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
      if(version_is_less(version:torVer, test_version:"0.2.1.22"))
      {
          security_message(torPort);
          exit(0);
      }

      if(version_is_less(version:torVer, test_version:"0.2.2.7.alpha"))
      {
        security_message(torPort);
        exit(0);
      }
    }
  }
}
