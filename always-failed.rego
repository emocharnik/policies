package terraform 

import input.tfplan as tfplan
import input.tfrun as tfrun



deny["always failed"]  {
    time.Sleep(5 * time.Minute)
    false
}
