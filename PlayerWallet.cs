using UnityEngine;
using UnityEngine.UI;

public class PlayerWallet : MonoBehaviour
{
    [SerializeField] private Score _score;
    [SerializeField] private Text _text;
    
    public float Money { get; private set; }

    private void Start()
    {
        Money = PlayerPrefs.GetFloat(nameof(Money));
        _text.text = $"Δενεγ: {Money}";
    }

    private void OnEnable()
    {
        _score.UpdateWallet += OnAddMoney;
    }

    private void OnDisable()
    {
        _score.UpdateWallet -= OnAddMoney;
    }

    private void OnAddMoney()
    {
        Money++;
        PlayerPrefs.SetFloat("Money", Money);
        _text.text = $"Δενεγ: {Money}";
    }

    public bool CheckSolvency(int price)
    {
        return Money >= price;
    }

    public void WidthdrawBear(int price)
    {
        Money -= price;
    }
}
