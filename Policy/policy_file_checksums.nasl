###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums.nasl 5456 2017-03-01 15:26:35Z cfi $
#
# Check File Checksums
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.103940");
  script_version("$Revision: 5456 $");
  script_name("File Checksums");
  script_tag(name:"last_modification", value:"$Date: 2017-03-01 16:26:35 +0100 (Wed, 01 Mar 2017) $");
  script_tag(name:"creation_date", value:"2013-08-14 16:47:16 +0200 (Wed, 14 Aug 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("login/SSH/Linux");

  script_add_preference(name:"Target checksum File", type:"file", value:"");
  script_add_preference(name:"List all and not only the first 100 entries", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"Checks the checksums (MD5 or SHA1) of specified files");
  script_tag(name:"insight", value:"The SSH protocol is used to log in and to gather the needed information");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit(0);
}

listall = script_get_preference("List all and not only the first 100 entries");

checksumlist = script_get_preference("Target checksum File");
if (!checksumlist)
  exit(0);

checksumlist = script_get_preference_file_content("Target checksum File");
if (!checksumlist)
  exit(0);

lines = split(checksumlist,keep:0);
split_checksumlist = lines;

line_count = max_index(lines);

if (line_count == 1 && lines[0] =~ "Checksum\|File\|Checksumtype(\|Only-Check-This-IP)?")
   exit(0); # empty file, just the header is present.

x = 0;

foreach line (lines) {
  x++;

  if (!eregmatch(pattern:"((Checksum\|File\|Checksumtype(\|Only-Check-This-IP)?)|([a-f0-9]{32,40}\|.*\|(sha1|md5)))",
                 string:line)) {
    if (x == line_count && eregmatch(pattern:"^$", string:line))
      continue;  # accept one empty line at the end of checksumlist.
    _error += 'Invalid line ' + line + ' in checksum File found. Checksumtest aborted.\n';
  }
}

if (_error)
  exit(0);


maxlist = 100;
include("ssh_func.inc");

port = get_kb_item("Services/ssh");
if (!port) {
  port = 22;
}

host_ip = get_host_ip();

sock = ssh_login_or_reuse_connection();
if (!sock) {
  error = get_ssh_error();
  if (!error)
    error = "No SSH Port or Connection!";
  log_message(port:port, data:error);
  exit(0);
}

# Check if it has the format of an MD5 hash
function check_md5(md5) {
  if (ereg(pattern:"^[a-f0-9]{32}$", string:md5))
    return TRUE;

  return FALSE;
}

# Check if it has the format of an SHA1 hash
function check_sha1(sha1) {
  if (ereg(pattern:"^[a-f0-9]{40}$", string:sha1))
    return TRUE;

  return FALSE;
}

# Check if it has the format of an IP address
function check_ip(ip) {
  if (ereg(pattern: "([0-9]{1,3}\.){3}[0-9]{1,3}$", string: ip))
    return TRUE;

  return FALSE;
}

function check_file(file) {
  unallowed = make_list("#",">","<",";",'\0',"!","'",'"',"$","%","&","(",")","?","`","*"," |","}","{","[","]");

  foreach ua (unallowed) {
    if (ua >< file)
      return FALSE;
  }

  if (!ereg(pattern:"^/.*$", string:file))
    return FALSE;

  return TRUE;
}

if (listall == "yes"){
  max = max_index(split_checksumlist);
} else {
  maxindex = max_index(split_checksumlist);
  if (maxindex < maxlist)
    max = maxindex;
  else
    max = maxlist;
}

for (i=0; i<max; i++) {
  val = split(split_checksumlist[i], sep:'|', keep:0);
  checksum = tolower(val[0]);
  filename = val[1];
  algorithm  = tolower(val[2]);

  if (max_index(val) == 4) {
    ip = val[3];
    if (!check_ip(ip: ip)) {
      if (tolower(ip) != "only-check-this-ip") {
        _error += filename + '|ip format error|error;\n';
      }
      continue;
    }
    if (ip && ip != host_ip)
      continue;
  }

  if (!checksum || !filename || !algorithm) {
    errorlog = "Error in file read";
    log_message(port:0, data:errorlog);
    continue;
  }

  if (!check_file(file:filename)) {
    if (tolower(filename) != 'file') {
      _error += filename + '|filename format error|error;\n';
    }
    continue;
  }

  if (algorithm == "md5") {
    if (!check_md5(md5:checksum)) {
      if (checksum != 'md5') {
        _error += filename + '|md5 format error|error;\n'; 
      }
      continue;
    }

    sshval = ssh_cmd(socket:sock, cmd:"LC_ALL=C md5sum " + " '" + filename + "'");
    if (sshval !~ ".*No such file or directory") {
      md5val = split(sshval, sep:' ', keep:0);
      if (tolower(md5val[0]) == checksum) {
        md5pass += filename + '|' + md5val[0] + '|pass;\n';
      } else {
        md5fail += filename + '|' + md5val[0] + '|fail;\n';
      }
    } else {
      md5error += filename + '|No such file or directory|error;\n';
    }
  } else {
    if (algorithm == "sha1") {
      if (!check_sha1(sha1:checksum)) {
        if (checksum != "sha1") {
          _error += filename + '|sha1 format error|error;\n'; 
        }
        continue;
      }

      sshval = ssh_cmd(socket:sock, cmd:"LC_ALL=C sha1sum " + " '" + filename + "'");
      if (sshval !~ ".*No such file or directory") {
        sha1val = split(sshval, sep:' ', keep:0);
          if (tolower(sha1val[0]) == checksum) {
            sha1pass += filename + '|' + sha1val[0] + '|pass;\n';
          } else {
            sha1fail += filename + '|' + sha1val[0] + '|fail;\n';
          }
      } else {
        sha1error += filename + '|No such file or directory|error;\n';
      }
    }
  }
}

if (_error) {
  report = 'Errors\n:' + _error;
  log_message(port:0, proto="ssh", data:report);
}

# Write results to KB for further checks and reporting
if (md5pass) {
  set_kb_item(name:"policy/md5cksum_ok", value:md5pass);
  replace_kb_item(name:"policy/checksum_ok", value:TRUE);
}
if (md5fail) {
  set_kb_item(name:"policy/md5cksum_fail", value:md5fail);
  replace_kb_item(name:"policy/checksum_fail", value:TRUE);
}
if (md5error) {
  set_kb_item(name:"policy/md5cksum_err", value:md5error);
  replace_kb_item(name:"policy/checksum_err", value:TRUE);
}

if (sha1pass) {
  set_kb_item(name:"policy/sha1cksum_ok", value:sha1pass);
  replace_kb_item(name:"policy/checksum_ok", value:TRUE);
}
if (sha1fail) {
  set_kb_item(name:"policy/sha1cksum_fail", value:sha1fail);
  replace_kb_item(name:"policy/checksum_fail", value:TRUE);
}
if (sha1error) {
  set_kb_item(name:"policy/sha1cksum_err", value:sha1error);
  replace_kb_item(name:"policy/checksum_err", value:TRUE);
}

exit(0);