###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sshd_gssapi_credential_disclosure_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# OpenSSH 'sshd' GSSAPI Credential Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902488");
  script_version("$Revision: 12006 $");
  script_cve_id("CVE-2005-2798");
  script_bugtraq_id(14729);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-16 12:24:22 +0530 (Wed, 16 Nov 2011)");
  script_name("OpenSSH 'sshd' GSSAPI Credential Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/16686");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1014845");
  script_xref(name:"URL", value:"https://lists.mindrot.org/pipermail/openssh-unix-announce/2005-September/000083.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod ");
  script_family("General");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass security
  restrictions and gain escalated privileges.");
  script_tag(name:"affected", value:"OpenSSH version prior to 4.2");
  script_tag(name:"insight", value:"The flaw is due to an error in handling GSSAPI credential delegation,
  Which allow GSSAPI credentials to be delegated to users who log in with
  methods other than GSSAPI authentication (e.g. public key) when the client
  requests it.");
  script_tag(name:"solution", value:"Upgrade OpenSSH to 4.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is running OpenSSH sshd with GSSAPI enabled and is prone
  to credential disclosure vulnerability.");
  script_xref(name:"URL", value:"http://www.openssh.com/");
  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/ssh");
if(!port){
  port = 22;
}

banner = get_kb_item("SSH/banner/" + port );
if(!banner){
  exit(0);
}

ver = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string:tolower(banner));

if(isnull(ver[1])){
 exit(0);
}

if(version_is_less(version:ver[1], test_version:"4.2"))
{
  auth = get_kb_item("SSH/supportedauth/" + port);
  if(auth)
  {
    if("gssapi" >< auth){
      security_message(port);
    }
  }
}
