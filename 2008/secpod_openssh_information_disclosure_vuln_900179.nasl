##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssh_information_disclosure_vuln_900179.nasl 4522 2016-11-15 14:52:19Z teissa $
# Description: OpenSSH CBC Mode Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

tag_impact = "Successful exploits will allow attackers to obtain four bytes of plaintext from
  an encrypted session.
  Impact Level: Application";
tag_affected = "- SSH Communications Security Tectia Client and Server version 6.0.4 and prior
  - SSH Communications Security Tectia ConnectSecure version 6.0.4 and prior
  - OpenSSH OpenSSH version 4.7p1 and prior";
tag_insight = "The flaw is due to the improper handling of errors within an SSH session
  encrypted with a block cipher algorithm in the Cipher-Block Chaining 'CBC' mode.";
tag_solution = "Upgrade to higher version
  http://www.openssh.com/portable.html";
tag_summary = "The host is installed with OpenSSH and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900179");
  script_version("$Revision: 4522 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-15 15:52:19 +0100 (Tue, 15 Nov 2016) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5161");
  script_bugtraq_id(32319);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("OpenSSH CBC Mode Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32760/");
  script_xref(name : "URL" , value : "http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name: "solution_type", value: "VendorFix");

  script_dependencies("gather-package-list.nasl", "ssh_detect.nasl");
  script_require_keys("ssh/login/uname");
  script_require_ports("Services/ssh", 22);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");

port = get_kb_item("Services/ssh");
if(!port){
  exit(0);
}
if("Linux" >!< get_kb_item("ssh/login/uname")){
  exit(0);
}

foreach item (get_kb_list("ssh/*/rpms"))
{
  openItem = egrep(pattern:"^openssh~([.0-9a-z]+)~.*$", string:item);
  if("openssh" >< openItem)
  {
    # Grep for versions 4.7p1 and prior
    if(ereg(pattern:"OpenSSH_([0-3](\..*)?|4\.[0-7](p[0-2])?)($|[^.0-9])",
      string:get_kb_item("SSH/banner/" + port))){
      security_message(port);
      exit(0);
    }
  }
}
