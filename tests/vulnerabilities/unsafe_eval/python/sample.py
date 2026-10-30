# Example of unsafe dynamic evaluation.

def calculate():
  user_input = input("Input to evaluate : ")
  result = eval(user_input)
  print(f"Result : {result}")


def normal_function():
  print("This is a normal function that does not use eval.")
  x = 10 + 5
  return x


if __name__ == "__main__":
  calculate()
  normal_function()