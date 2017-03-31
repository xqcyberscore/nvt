###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_28444.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# OpenSSH X Connections Session Hijacking Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "OpenSSH is prone to a vulnerability that allows attackers to hijack
forwarded X connections.

Successfully exploiting this issue may allow an attacker run arbitrary
shell commands with the privileges of the user running the affected
application.

This issue affects OpenSSH 4.3p2; other versions may also be affected.

NOTE: This issue affects the portable version of OpenSSH and may not
      affect OpenSSH running on OpenBSD.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100584);
 script_version("$Revision: 5323 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
 script_bugtraq_id(28444);
 script_cve_id("CVE-2008-1483");

 script_name("OpenSSH X Connections Session Hijacking Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/28444");
 script_xref(name : "URL" , value : "http://support.apple.com/kb/HT3137");
 script_xref(name : "URL" , value : "http://www.openbsd.org/errata41.html");
 script_xref(name : "URL" , value : "http://www.openbsd.org/errata42.html");
 script_xref(name : "URL" , value : "http://www.openbsd.org/errata43.html");
 script_xref(name : "URL" , value : "http://www.openssh.com/txt/release-5.0");
 script_xref(name : "URL" , value : "http://www.openssh.com");
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=590180");
 script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=463011");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/492447");
 script_xref(name : "URL" , value : "http://aix.software.ibm.com/aix/efixes/security/ssh_advisory.asc");
 script_xref(name : "URL" , value : "http://support.avaya.com/elmodocs2/security/ASA-2008-205.htm");
 script_xref(name : "URL" , value : "http://www.globus.org/mail_archive/security-announce/2008/04/msg00000.html");
 script_xref(name : "URL" , value : "http://support.attachmate.com/techdocs/2374.html#Security_Updates_in_7.0_SP1");
 script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-237444-1");

 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_mandatory_keys("openssh/detected");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ssh");
if(!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

version = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: tolower(banner));
if(isnull(version[1]))exit(0);
vers = str_replace(find:"p", replace:".p", string:version[1]);

if(version_is_less(version: vers, test_version: "4.3.p2")) {
  security_message(port);
  exit(0);
}

exit(0);
