###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssh CESA-2012:0884 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "OpenSSH is OpenBSD's Secure Shell (SSH) protocol implementation. These
  packages include the core files necessary for the OpenSSH client and
  server.

  A denial of service flaw was found in the OpenSSH GSSAPI authentication
  implementation. A remote, authenticated user could use this flaw to make
  the OpenSSH server daemon (sshd) use an excessive amount of memory, leading
  to a denial of service. GSSAPI authentication is enabled by default
  (&quot;GSSAPIAuthentication yes&quot; in &quot;/etc/ssh/sshd_config&quot;). (CVE-2011-5000)
  
  These updated openssh packages also provide fixes for the following bugs:
  
  * SSH X11 forwarding failed if IPv6 was enabled and the parameter
  X11UseLocalhost was set to &quot;no&quot;. Consequently, users could not set X
  forwarding. This update fixes sshd and ssh to correctly bind the port for
  the IPv6 protocol. As a result, X11 forwarding now works as expected with
  IPv6. (BZ#732955)
  
  * The sshd daemon was killed by the OOM killer when running a stress test.
  Consequently, a user could not log in. With this update, the sshd daemon
  sets its oom_adj value to -17. As a result, sshd is not chosen by OOM
  killer and users are able to log in to solve problems with memory.
  (BZ#744236)
  
  * If the SSH server is configured with a banner that contains a backslash
  character, then the client will escape it with another &quot;\&quot; character, so it
  prints double backslashes. An upstream patch has been applied to correct
  the problem and the SSH banner is now correctly displayed. (BZ#809619)
  
  In addition, these updated openssh packages provide the following
  enhancements:
  
  * Previously, SSH allowed multiple ways of authentication of which only one
  was required for a successful login. SSH can now be set up to require
  multiple ways of authentication. For example, logging in to an SSH-enabled
  machine requires both a passphrase and a public key to be entered. The
  RequiredAuthentications1 and RequiredAuthentications2 options can be
  configured in the /etc/ssh/sshd_config file to specify authentications that
  are required for a successful login. For example, to set key and password
  authentication for SSH version 2, type:
  
  echo &quot;RequiredAuthentications2 publickey,password&quot; &gt;&gt; /etc/ssh/sshd_config
  
  For more information on the aforementioned /etc/ssh/sshd_config options,
  refer to the sshd_config man page. (BZ#657378)
  
  * Previously, OpenSSH could use the Advanced Encryption Standard New
  Instructions (AES-NI) instruction set only with the AES Cipher-block
  chaining (CBC) cipher. This update adds  ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "openssh on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-July/018719.html");
  script_id(881183);
  script_version("$Revision: 8249 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 07:29:56 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:36:31 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-5000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2012:0884");
  script_name("CentOS Update for openssh CESA-2012:0884 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of openssh");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
