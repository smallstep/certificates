# step package configuration
class tls_server(
  $version = false,
) {
  if !$version {
    fail("class ${name}: version cannot be empty")
  }

  file {
    '/usr/local/lib/step/.step/secrets/provisioner_pupppet_pass': # Get this from Hiera.
      ensure  => file,
      mode    => '0644',
      owner   => 'step';
  }

  $step = "/opt/smallstep/bin/step"
  $step_path = "/usr/local/lib/step/.step"
  $secrets = "${step_path}/usr/local/lib/step/.step"
  service { $name:
    ensure    => running,
    start => "/usr/local/bin/tls_server --token $(${step} token foo.com --ca-url=ca.smallstep.com --root=${secrets}/root_ca.crt --password-file=${secrets}/intermediate_pass)",
    provider  => 'systemd',
  }
}
