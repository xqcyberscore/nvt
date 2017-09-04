###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_authentication_bypass_vuln.nasl 7015 2017-08-28 11:51:24Z teissa $
#
# SSH SSH-1 Protocol Authentication Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allows remote attackers to bypass security
  restrictions and to obtain a client's public host key during a connection
  attempt and use it to open and authenticate an SSH session to another
  server with the same access.
  Impact Level: Application";
tag_affected = "SSH Protocol Version SSH-1";
tag_insight = "The flaw is due to an error in the SSH-1 protocol authentication
  process when encryption is disabled, which allows client authentication to
  be forwarded by a malicious server to another server.";
tag_solution = "Upgrade to SSH SSH-2,
  For updates refer to http://www.openssh.com/";
tag_summary = "The host is running SSH and is prone to authentication
  bypass vulnerability.";

if(description)
{
  script_id(801993);
  script_version("$Revision: 7015 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-28 13:51:24 +0200 (Mon, 28 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2001-1473");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SSH SSH-1 Protocol Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/684820");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/6603");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ssh_proto_version.nasl");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

## Get the default port
port = get_kb_item("Services/ssh");
if(!port){
  port = 22;
}

## Get the SSH banner
banner = get_kb_item("SSH/banner/" + port );
if(!banner){
  exit(0);
}

## Get the supported protocols versions from kb
dnnVer = get_kb_item("SSH/supportedversions/" + port);

## Check the SSH protocol version
if((dnnVer =~ "'1\..*") && !(dnnVer =~ "'[2-9]\..*")){
  security_message(0);
}
